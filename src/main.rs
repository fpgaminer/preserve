// Debugging only
// #![feature(alloc_system)]
// extern crate alloc_system;

extern crate acd;
extern crate ceph_rust;
#[macro_use]
extern crate clap;
extern crate crypto;
extern crate libc;
#[macro_use]
extern crate log;
extern crate lzma;
#[macro_use]
pub mod newtype_macros;
extern crate rustc_serialize;
extern crate rand;
extern crate tempdir;
extern crate time;
extern crate url;

mod archive;
mod backend;
mod block;
mod cmds;
mod error;
mod keystore;
mod logger;

use logger::Logger;
use log::LogLevelFilter;
use clap::{App, AppSettings, SubCommand};


fn main() {
    let matches = App::new("preserve")
        .version(crate_version!())
        .about("Robust, Encrypted Backup")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .setting(AppSettings::VersionlessSubcommands)
        .setting(AppSettings::UnifiedHelpMessage)
        .setting(AppSettings::ColoredHelp)
        .args_from_usage("--logfile=[LOGFILE]  'Sets a file to write a log to'
							 --verbose            \
                          'Be verbose'")
        .subcommand(SubCommand::with_name("create")
            .about("create a new backup")
            .setting(AppSettings::UnifiedHelpMessage)
            .setting(AppSettings::ColoredHelp)
            .args_from_usage("--keyfile=<KEYFILE>  'Sets the keyfile to use'
								 \
                              --backend=<BACKEND>  'Sets the backend to use'
								 \
                              --dereference        'Follow symlinks'
								 <NAME>               \
                              'Unique name for this backup'
								 <PATH>               'The \
                              path to backup'"))
        .subcommand(SubCommand::with_name("keygen")
            .about("create a new keyfile")
            .setting(AppSettings::UnifiedHelpMessage)
            .setting(AppSettings::ColoredHelp)
            .args_from_usage("--keyfile=[FILE] 'Write the new keyfile to FILE'"))
        .subcommand(SubCommand::with_name("list")
            .about("list existing backups")
            .setting(AppSettings::UnifiedHelpMessage)
            .setting(AppSettings::ColoredHelp)
            .args_from_usage("--keyfile=<KEYFILE>  'Sets the keyfile to use'
								 \
                              --backend=<BACKEND>  'Sets the backend to use'"))
        .subcommand(SubCommand::with_name("restore")
            .about("restore an existing backup")
            .setting(AppSettings::UnifiedHelpMessage)
            .setting(AppSettings::ColoredHelp)
            .args_from_usage("--keyfile=<KEYFILE>  'Sets the keyfile to use'
								 \
                              --backend=<BACKEND>  'Sets the backend to use'
								 \
                              --hard-dereference   'Dereference hardlinks'
								 \
                              --debug-decrypt      'Just fetch and decrypt the archive; no \
                              decompression, parsing, or extraction'
								 <NAME>               \
                              'Name of the backup to restore'
								 [PATH]               \
                              'Where to extract the backup to'"))
        .subcommand(SubCommand::with_name("verify")
            .about("verify the integrity of an existing backup and all encrypted blocks it \
                    references")
            .setting(AppSettings::UnifiedHelpMessage)
            .setting(AppSettings::ColoredHelp)
            .args_from_usage("--keyfile=<KEYFILE>  'Sets the keyfile to use'
								 \
                              --backend=<BACKEND>  'Sets the backend to use'
								 <NAME>               \
                              'The name of the backup to verify'"))
        .get_matches();

    Logger::init(LogLevelFilter::Info, matches.value_of("logfile"));

    match matches.subcommand() {
        ("create", Some(sub_m)) => cmds::create::execute(sub_m),
        ("keygen", Some(sub_m)) => cmds::keygen::execute(sub_m),
        ("list", Some(sub_m)) => cmds::list::execute(sub_m),
        ("restore", Some(sub_m)) => cmds::restore::execute(sub_m),
        ("verify", Some(sub_m)) => cmds::verify::execute(sub_m),
        _ => panic!("Unknown subcommand"),
    }
}
