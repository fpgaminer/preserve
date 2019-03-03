use crate::keystore::KeyStore;
use crate::backend;
use clap::ArgMatches;
use log::{error, warn};


pub fn execute(args: &ArgMatches) {
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

	let encrypted_archive_names = match backend.list_archives() {
		Ok(names) => names,
		Err(err) => {
			error!("There was a problem listing the archives: {}", err);
			return;
		}
	};

	// TODO: Push into a vec, sort alphabetically, and then print
	for (archive_id, encrypted_archive_name) in &encrypted_archive_names {
		let archive_name = match keystore.decrypt_archive_name(archive_id, encrypted_archive_name) {
			Ok(name) => name,
			Err(err) => {
				warn!("Could not decrypt one of the archive names belonging to ArchiveID: {}, because: {}", archive_id.to_string(), err);
				continue;
			}
		};

		println!("{}", archive_name);
	}

	if encrypted_archive_names.is_empty() {
		println!("No archives found");
	}
}
