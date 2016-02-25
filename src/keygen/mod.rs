use keystore::KeyStore;
use getopts::Options;
use std::io;
use std::fs::File;
use std::io::{BufWriter, Write};


pub fn execute(args: &[String]) {
	let mut opts = Options::new();
	opts.optopt("", "keyfile", "set output filename", "NAME");

	let matches = match opts.parse(args) {
		Ok(m) => m,
		Err(err) => panic!(err.to_string())
	};

	let mut writer: BufWriter<Box<Write>> = BufWriter::new(match matches.opt_str("keyfile") {
		Some(path) => Box::new(File::create(path).unwrap()),
		None => Box::new(io::stdout()),
	});

	let keystore = KeyStore::new();

	keystore.save(&mut writer);
}
