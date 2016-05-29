use keystore::KeyStore;
use std::fs::OpenOptions;
use std::io::{self, BufWriter, Write};
use clap::ArgMatches;


pub fn execute(args: &ArgMatches) {
	let mut writer: BufWriter<Box<Write>> = BufWriter::new(match args.value_of("keyfile") {
		Some(path) => {
			// Won't overwrite existing files
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
	});

	let keystore = KeyStore::new();

	keystore.save(&mut writer);
}
