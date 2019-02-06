use clap::ArgMatches;
use log::{error, warn};
use crate::keystore::KeyStore;
use crate::backend::{self, Backend};
use crate::archive::{Archive, File};
use crate::error::Result;
use std::collections::{HashMap, HashSet};


pub fn execute(args: &ArgMatches) {
	let backup1_name = args.value_of("NAME1").expect("internal error");
	let backup2_name = args.value_of("NAME2").expect("internal error");
	let args_keyfile = args.value_of("keyfile").expect("internal error");
	let args_backend = args.value_of("backend").expect("internal error");

	let keystore = match KeyStore::load_from_path(args_keyfile) {
		Ok(keystore) => keystore,
		Err(err) => {
			error!("Unable to load keyfile: {}", err);
			return;
		}
	};

	let mut backend = match backend::backend_from_backend_path(args_backend) {
		Ok(backend) => backend,
		Err(err) => {
			error!("Unable to load backend: {}", err);
			return;
		}
	};

	let mut archive1 = match fetch_and_decrypt_archive(backup1_name, &keystore, &mut *backend) {
		Ok(archive) => archive,
		Err(err) => {
			error!("{}", err);
			return;
		}
	};

	let mut archive2 = match fetch_and_decrypt_archive(backup2_name, &keystore, &mut *backend) {
		Ok(archive) => archive,
		Err(err) => {
			error!("{}", err);
			return;
		}
	};

	if archive1.version != 0x00000001 || archive2.version != 0x00000001 {
		error!("Unsupported archive version");
		return;
	}

	if archive1.original_path != archive2.original_path {
		warn!("The original paths for the two archives differ.  This may or may not be important depending on what you're comparing.");
	}

	// TODO: Need to handle hardlinks properly?
	// TODO: For now, we know that preserve stores the list of blocks for all files, even those with hardlink_ids, so we can ignore the hardlink_id field.
	// TODO: Basically this means that we'll still detect differences in file contents, but we can't report if hardlinks themselves have changed.
	for file in &mut archive1.files {
		file.hardlink_id = None;
	}

	for file in &mut archive2.files {
		file.hardlink_id = None;
	}

	let archive1_hashmap: HashMap<&String, &File> = archive1.files.iter().map(|file| (&file.path, file)).collect();
	let archive2_hashmap: HashMap<&String, &File> = archive2.files.iter().map(|file| (&file.path, file)).collect();

	let archive1_hashset: HashSet<&String> = archive1_hashmap.keys().cloned().collect();// archive1.files.iter().map(|file| &file.path).collect();
	let archive2_hashset: HashSet<&String> = archive2_hashmap.keys().cloned().collect();// archive2.files.iter().map(|file| &file.path).collect();

	// Files in archive2 that aren't in archive1.
	archive2_hashset.difference(&archive1_hashset)
		.for_each(|path| {
			println!("Added: {}", path)
		});
	
	// Files in archive1 that aren't in archive2.
	archive1_hashset.difference(&archive2_hashset)
		.for_each(|path| {
			println!("Deleted: {}", path)
		});
	
	// Files that are in both, but have changed.
	archive2_hashset.intersection(&archive1_hashset)
		.filter(|&path| {
			let version1 = archive1_hashmap.get(path).expect("internal error");
			let version2 = archive2_hashmap.get(path).expect("internal error");

			version1 != version2
		})
		.for_each(|path| {
			println!("Changed: {}", path);
		});
}


fn fetch_and_decrypt_archive(name: &str, keystore: &KeyStore, backend: &mut Backend) -> Result<Archive> {
	let encrypted_archive_name = keystore.encrypt_archive_name(&name)?;
	let encrypted_archive = backend.fetch_archive(&encrypted_archive_name)?;
	Archive::decrypt(&encrypted_archive_name, &encrypted_archive, &keystore)
}