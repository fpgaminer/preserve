use keystore::KeyStore;
use std::fs;
use std::io::BufReader;
use backend::{FileBackend, AcdBackend, Backend};
use clap::ArgMatches;


pub fn execute(args: &ArgMatches) {
	let mut reader = BufReader::new(fs::File::open(args.value_of("keyfile").unwrap()).unwrap());

	let keystore = KeyStore::load(&mut reader);
	let mut backend: Box<Backend> = {
		match &args.value_of("backend").unwrap()[..] {
			"acd" => Box::new(AcdBackend::new()),
			"file" => Box::new(FileBackend::new(args.value_of("backend-path").unwrap())),
			x => panic!("Unknown backend {}", x),
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
