extern crate rustc_serialize;
extern crate crypto;
extern crate rand;
extern crate getopts;
extern crate lzma;
extern crate libc;
extern crate acd;
extern crate tempdir;
extern crate rusqlite;
#[macro_use]
extern crate log;
extern crate time;

#[macro_use]
pub mod newtype_macros;
mod keystore;
mod archive;
mod backend;
mod block;
mod cmds;
mod logger;

use std::env;
use logger::Logger;
use log::LogLevelFilter;


const USAGE: &'static str = "
Usage:
	preserve <command> [options] [<args...]

Commands:
	keygen    Generate a keyfile
	create    Create a new backup
	restore   Restore a backup
	list      List the names of all backups
	verify    Verify a backup

See 'preserve help <command>' for more information on a specific command.
";


fn main() {
	Logger::init(LogLevelFilter::Info).unwrap();

	let args: Vec<String> = env::args().collect();

	if args.len() < 2 {
		println!("{}", USAGE);
		return;
	}

	match args[1].as_ref() {
		"keygen" => {
			cmds::keygen::execute(&args[2..]);
		},
		"create" => {
			cmds::create::execute(&args[2..]);
		},
		"restore" => {
			cmds::restore::execute(&args[2..]);
		},
		"verify" => {
			cmds::verify::execute(&args[2..]);
		},
		"list" => {
			cmds::list::execute(&args[2..]);
		},
		_ => {
			println!("{}", USAGE);
			return;
		}
	}
}
