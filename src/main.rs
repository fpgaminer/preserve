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
pub mod newtype_macros;
mod keystore;
mod archive;
mod backend;
mod block;
mod keygen;
mod create;
mod restore;
mod verify;
mod list;

use std::env;


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
	let args: Vec<String> = env::args().collect();

	if args.len() < 2 {
		println!("{}", USAGE);
		return;
	}

	match args[1].as_ref() {
		"keygen" => {
			keygen::execute(&args[2..]);
		},
		"create" => {
			create::execute(&args[2..]);
		},
		"restore" => {
			restore::execute(&args[2..]);
		},
		"verify" => {
			verify::execute(&args[2..]);
		},
		"list" => {
			list::execute(&args[2..]);
		},
		_ => {
			println!("{}", USAGE);
			return;
		}
	}
}