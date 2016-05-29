use keystore::{KeyStore, Secret};
use std::fs;
use std::io::{BufReader, stderr, Write};
use std::collections::HashSet;
use rustc_serialize::hex::FromHex;
use backend::{FileBackend, AcdBackend, Backend};
use archive::{Archive, File};
use rand::{thread_rng, Rng};
use clap::ArgMatches;


pub fn execute(args: &ArgMatches) {
	let backup_name = args.value_of("NAME").unwrap();

	let mut reader = BufReader::new(fs::File::open(args.value_of("keyfile").unwrap()).unwrap());
	let keystore = KeyStore::load(&mut reader);
	let mut backend: Box<Backend> = {
		match &args.value_of("backend").unwrap()[..] {
			"acd" => Box::new(AcdBackend::new()),
			"file" => Box::new(FileBackend::new(args.value_of("backend-path").unwrap())),
			x => panic!("Unknown backend {}", x),
		}
	};

	let encrypted_archive_name = keystore.encrypt_archive_name(&backup_name);
	let encrypted_archive = backend.fetch_archive(&encrypted_archive_name);

	let archive = Archive::decrypt(&encrypted_archive_name, &encrypted_archive, &keystore);

	if archive.version != 0x00000001 {
		panic!("Unsupported archive version");
	}

	let mut block_list = HashSet::new();

	build_block_list(&archive.files, &mut block_list);
	let mut block_list: Vec<&String> = block_list.iter().collect();
	// TODO: Verify what RNG rust is going to use here.  We don't need crypto secure RNG, but do
	// need something good.
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
		let secret = Secret::from_slice(&secret_str.from_hex().unwrap()).unwrap();
		let block_id = keystore.block_id_from_block_secret(&secret);

		let encrypted_block = backend.fetch_block(&block_id);

		if !keystore.verify_encrypted_block(&block_id, &encrypted_block) {
			writeln!(stderr(), "CRITICAL ERROR: Block {} is corrupt.  You should save a copy of the corrupted block, delete it, and then rearchive the files that created this archive.  That should recreate the block.", block_id.to_string()).unwrap();
			corrupted_blocks.push(block_id.to_string());
		}

		if idx % 32 == 0 {
			info!("{:.2}% ({}/{})", 100.0 * (idx + 1) as f64 / block_list.len() as f64, idx + 1, block_list.len());
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
