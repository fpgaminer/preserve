use std::collections::HashSet;
use std::path::PathBuf;

use archive::{Archive, File};
use backend::{self, Backend};
use clap::ArgMatches;
use keystore::{KeyStore, Secret};
use rand::{thread_rng, Rng};
use rustc_serialize::hex::FromHex;


pub fn execute(args: &ArgMatches, config_dir: Option<PathBuf>) {
    let backup_name = args.value_of("NAME").expect("internal error");
    let args_backend = args.value_of("backend").expect("internal error");

    let keystore = if args.is_present("vault") {
        match KeyStore::load_from_vault(config_dir.clone()) {
            Ok(keystore) => keystore,
            Err(err) => {
                error!("Unable to load keyfile: {}", err);
                return;
            }
        }
    } else {
        let args_keyfile = args.value_of("keyfile")
            .expect("internal error.  keyfile not specified");
        match KeyStore::load_from_path(args_keyfile) {
            Ok(keystore) => keystore,
            Err(err) => {
                error!("Unable to load keyfile: {}", err);
                return;
            }
        }
    };

    let mut backend = match backend::backend_from_backend_path(args_backend, config_dir) {
        Ok(backend) => backend,
        Err(err) => {
            error!("Unable to load backend: {}", err);
            return;
        }
    };

    let encrypted_archive_name = match keystore.encrypt_archive_name(&backup_name) {
        Ok(name) => name,
        Err(err) => {
            error!("{}", err);
            return;
        }
    };
    let encrypted_archive = match backend.fetch_archive(&encrypted_archive_name) {
        Ok(archive) => archive,
        Err(err) => {
            error!("{}", err);
            return;
        }
    };
    let archive = match Archive::decrypt(&encrypted_archive_name, &encrypted_archive, &keystore) {
        Ok(archive) => archive,
        Err(err) => {
            error!("{}", err);
            return;
        }
    };

    if archive.version != 0x00000001 {
        error!("Unsupported archive version");
        return;
    }

    let mut block_list = HashSet::new();

    build_block_list(&archive.files, &mut block_list);
    let mut block_list: Vec<&String> = block_list.iter().collect();
    // We shuffle so that if verification is terminated it can be run again (multiple times) and
    // probablistically cover all blocks.
    thread_rng().shuffle(&mut block_list);

    verify_blocks(&block_list, &keystore, &mut *backend);
}


fn build_block_list(files: &[File], block_list: &mut HashSet<String>) {
    for file in files {
        for secret_str in &file.blocks {
            block_list.insert(secret_str.clone());
        }
    }
}


fn verify_blocks(block_list: &[&String], keystore: &KeyStore, backend: &mut Backend) {
    let mut corrupted_blocks = Vec::new();

    for (idx, secret_str) in block_list.iter().enumerate() {
        let secret = {
            let secret_str_hex = match secret_str.from_hex() {
                Ok(s) => s,
                Err(_) => {
                    error!("CRITICAL ERROR: A Block secret contained invalid hex characters.  \
                            This is not normal and should never happen.  Probably the archive's \
                            version got mixed up somehow.  Secret: '{}'",
                           secret_str);
                    continue;
                }
            };
            match Secret::from_slice(&secret_str_hex) {
                Some(s) => s,
                None => {
                    error!("CRITICAL ERROR: A Block secret was not the right number of bytes.  \
                            This is not normal and should never happen.  Probably the archive's \
                            version got mixed up somehow.  Secret: '{}'",
                           secret_str);
                    continue;
                }
            }
        };
        let block_id = keystore.block_id_from_block_secret(&secret);

        // TODO: Differentiate between a missing block and an error.  Missing blocks would be
        // critical errors.
        let encrypted_block = match backend.fetch_block(&block_id) {
            Ok(block) => block,
            Err(err) => {
                error!("A problem occured while fetching the block '{}': {}",
                       block_id.to_string(),
                       err);
                continue;
            }
        };

        if !keystore.verify_encrypted_block(&block_id, &encrypted_block) {
            error!("CRITICAL ERROR: Block {} is corrupt.  You should save a copy of the \
                    corrupted block, delete it, and then rearchive the files that created this \
                    archive.  That should recreate the block.",
                   block_id.to_string());
            corrupted_blocks.push(block_id.to_string());
        }

        if idx % 32 == 0 {
            info!("{:.2}% ({}/{})",
                  100.0 * (idx + 1) as f64 / block_list.len() as f64,
                  idx + 1,
                  block_list.len());
        }
    }

    if !corrupted_blocks.is_empty() {
        error!("The following corrupted blocks were found:");
        for block_id in corrupted_blocks {
            error!("{}", block_id);
        }
    } else {
        info!("No corrupted blocks were found");
    }
}
