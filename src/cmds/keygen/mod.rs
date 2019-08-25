use crate::keystore::KeyStore;
use std::fs::OpenOptions;
use std::io::{self, BufWriter, Write};
use clap::ArgMatches;
use log::error;


pub fn execute(args: &ArgMatches) {
	// Open output file/stdout for writing
	let file: Box<dyn Write> = match args.value_of("keyfile") {
		Some(path) => {
			// Won't overwrite existing file
			let file = match OpenOptions::new().write(true).create_new(true).open(path) {
				Ok(f) => f,
				Err(e) => if e.kind() == io::ErrorKind::AlreadyExists {
					error!("'{}' already exists.", path);
					return;
				} else {
					error!("Could not open '{}' for writing: {}", path, e);
					return;
				},
			};
			Box::new(file)
		},
		None => Box::new(io::stdout()),
	};
	let mut writer = BufWriter::new(file);

	// Create a new keystore
	let keystore = KeyStore::new();

	// Save the keystore to the destination (file/stdout)
	match keystore.save(&mut writer) {
		Ok(_) => (),
		Err(err) => {
			error!("Could not write to keyfile: {}", err);
			return;
		}
	}
}
