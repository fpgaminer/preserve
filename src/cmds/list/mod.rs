use keystore::KeyStore;
use getopts::Options;
use std::fs;
use std::io::BufReader;
use backend::{FileBackend, AcdBackend, Backend};


pub fn execute(args: &[String]) {
	let mut opts = Options::new();
	opts.reqopt("", "keyfile", "set keyfile", "NAME");
	opts.reqopt("", "backend", "set backend", "BACKEND");
	opts.optopt("", "backend-path", "set backend path", "PATH");

	let matches = match opts.parse(args) {
		Ok(m) => m,
		Err(err) => panic!(err.to_string())
	};

	let mut reader = BufReader::new(match matches.opt_str("keyfile") {
		Some(path) => fs::File::open(path).unwrap(),
		None => panic!("missing keyfile option"),
	});

	let keystore = KeyStore::load(&mut reader);
	let mut backend: Box<Backend> = {
		match &matches.opt_str("backend").unwrap()[..] {
			"acd" => Box::new(AcdBackend::new()),
			"file" => Box::new(FileBackend::new(matches.opt_str("backend-path").unwrap())),
			x => panic!("Unknown backend {}", x),
		}
	};

	let encrypted_archive_names = backend.list_archives();

	for encrypted_archive_name in &encrypted_archive_names {
		let archive_name = keystore.decrypt_archive_name(encrypted_archive_name);

		println!("{}", archive_name);
	}

	if encrypted_archive_names.is_empty() {
		println!("No archives found");
	}
}
