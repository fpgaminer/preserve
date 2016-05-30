use keystore::KeyStore;
use backend;
use clap::ArgMatches;


pub fn execute(args: &ArgMatches) {
	let args_keyfile = args.value_of("keyfile").unwrap();
	let args_backend = args.value_of("backend").unwrap();

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

	let encrypted_archive_names = backend.list_archives();

	// TODO: Push into a vec, sort alphabetically, and then print
	for encrypted_archive_name in &encrypted_archive_names {
		let archive_name = keystore.decrypt_archive_name(encrypted_archive_name);

		println!("{}", archive_name);
	}

	if encrypted_archive_names.is_empty() {
		println!("No archives found");
	}
}
