// Debugging only
// #![feature(alloc_system)]
// extern crate alloc_system;

extern crate acd;
#[cfg(feature = "ceph")]
extern crate ceph_rust;
#[macro_use]
extern crate clap;
extern crate crypto;
#[cfg(feature = "gluster")]
extern crate gfapi_sys;
extern crate hashicorp_vault as vault;
#[macro_use]
extern crate json;
extern crate libc;
#[macro_use]
extern crate log;
extern crate lzma;
#[macro_use]
pub mod newtype_macros;
extern crate rand;
extern crate rustc_serialize;
extern crate rusqlite;
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

use clap::{App, AppSettings, Arg, SubCommand};
use logger::Logger;
use log::LogLevelFilter;

use std::path::PathBuf;
use std::str::FromStr;

fn main() {
    let matches = App::new("preserve")
        .version(crate_version!())
        .about("Robust, Encrypted Backup")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .setting(AppSettings::VersionlessSubcommands)
        .setting(AppSettings::UnifiedHelpMessage)
        .setting(AppSettings::ColoredHelp)
        .arg(Arg::with_name("logfile")
            .help("Sets the file to write the logs to")
            .long("logfile")
            .takes_value(true)
            .required(false))
        .arg(Arg::with_name("loglevel")
            .help("Sets the level to write the logs at")
            .long("loglevel")
            .takes_value(true)
            .default_value("info")
            .possible_values(&["off", "error", "warn", "info", "debug", "trace"])
            .required(false))
        .arg(Arg::with_name("verbose")
            .help("Be verbose")
            .long("verbose")
            .takes_value(false)
            .required(false))
        .arg(Arg::with_name("configdir")
            .help("The directory where all config files can be found")
            .long("configdir")
            .takes_value(true)
            .required(false))
        .subcommand(SubCommand::with_name("create")
            .about("create a new backup")
            .setting(AppSettings::UnifiedHelpMessage)
            .setting(AppSettings::ColoredHelp)
            .arg(Arg::with_name("keyfile")
                .help("Sets the keyfile to use")
                .long("keyfile")
                .takes_value(true)
                .conflicts_with("vault")
                .required(false))
            .arg(Arg::with_name("vault")
                .long("vault")
                .help("Use keyfile from Vault")
                .takes_value(false)
                .required(false))
            .arg(Arg::with_name("backend")
                .long("backend")
                .help("Sets the backend to use")
                .takes_value(true)
                .required(true))
            .arg(Arg::with_name("dereference")
                .long("dereference")
                .help("Follow symlinks")
                .required(false))
            .arg(Arg::with_name("NAME")
                .help("Unique name for this backup")
                .takes_value(true)
                .required(true))
            .arg(Arg::with_name("PATH")
                .help("Path to backup")
                .takes_value(true)
                .required(true)))
        .subcommand(SubCommand::with_name("keygen")
            .about("create a new keyfile")
            .setting(AppSettings::UnifiedHelpMessage)
            .setting(AppSettings::ColoredHelp)
            .arg(Arg::with_name("keyfile")
                .help("Write the new keyfile to FILE")
                .long("keyfile")
                .takes_value(true)
                .conflicts_with("vault")
                .required(true))
            .arg(Arg::with_name("vault")
                .long("vault")
                .help("Store the keyfile in Vault")
                .takes_value(false)
                .required(true)))
        .subcommand(SubCommand::with_name("list")
            .about("list existing backups")
            .setting(AppSettings::UnifiedHelpMessage)
            .setting(AppSettings::ColoredHelp)
            .arg(Arg::with_name("keyfile")
                .help("Sets the keyfile to use")
                .long("keyfile")
                .takes_value(true)
                .conflicts_with("vault")
                .required(true))
            .arg(Arg::with_name("vault")
                .long("vault")
                .help("Use keyfile from Vault")
                .takes_value(false)
                .required(true))
            .arg(Arg::with_name("backend")
                .long("backend")
                .help("Sets the backend to use")
                .takes_value(true)
                .required(true))
            .arg(Arg::with_name("json")
                .long("json")
                .help("Format the output as json")
                .required(false)))
        .subcommand(SubCommand::with_name("restore")
            .about("restore an existing backup")
            .setting(AppSettings::UnifiedHelpMessage)
            .setting(AppSettings::ColoredHelp)
            .arg(Arg::with_name("keyfile")
                .help("Sets the keyfile to use")
                .long("keyfile")
                .takes_value(true)
                .conflicts_with("vault")
                .required(true))
            .arg(Arg::with_name("vault")
                .long("vault")
                .help("Use keyfile from Vault")
                .takes_value(false)
                .required(true))
            .arg(Arg::with_name("backend")
                .long("backend")
                .help("Sets the backend to use")
                .takes_value(true)
                .required(true))
            .arg(Arg::with_name("hard-dereference")
                .long("hard-dereference")
                .help("Dereference symlinks")
                .required(false))
            .arg(Arg::with_name("debug-decrypt")
                .long("debug-decrypt")
                .required(false)
                .help("Fetch and decrypt the archive; no decompression, parsing or extraction"))
            .arg(Arg::with_name("NAME")
                .help("Name of the backup to retore")
                .takes_value(true)
                .required(true))
            .arg(Arg::with_name("PATH")
                .help("Where to backup extract the backup to")
                .takes_value(true)
                .required(true)))
        .subcommand(SubCommand::with_name("verify")
            .about("verify the integrity of an existing backup and all encrypted blocks it \
                    references")
            .setting(AppSettings::UnifiedHelpMessage)
            .setting(AppSettings::ColoredHelp)
            .arg(Arg::with_name("keyfile")
                .help("Sets the keyfile to use")
                .long("keyfile")
                .takes_value(true)
                .conflicts_with("vault")
                .required(true))
            .arg(Arg::with_name("vault")
                .long("vault")
                .help("Use keyfile from Vault")
                .takes_value(false)
                .required(true))
            .arg(Arg::with_name("backend")
                .long("backend")
                .help("Sets the backend to use")
                .takes_value(true)
                .required(true))
            .arg(Arg::with_name("NAME")
                .help("The name of the backup to verify")
                .takes_value(true)
                .required(true)))
        .get_matches();
    // This should be safe since clap already validates that a valid value is input here
    let loglevel = LogLevelFilter::from_str(matches.value_of("loglevel").unwrap()).unwrap();

    Logger::init(loglevel, matches.value_of("logfile"));

    let config_dir = if matches.is_present("configdir") {
        Some(PathBuf::from(matches.value_of("configdir").unwrap()))
    } else {
        None
    };

    match matches.subcommand() {
        ("create", Some(sub_m)) => cmds::create::execute(sub_m, config_dir),
        ("keygen", Some(sub_m)) => cmds::keygen::execute(sub_m, config_dir),
        ("list", Some(sub_m)) => cmds::list::execute(sub_m, config_dir),
        ("restore", Some(sub_m)) => cmds::restore::execute(sub_m, config_dir),
        ("verify", Some(sub_m)) => cmds::verify::execute(sub_m, config_dir),
        _ => panic!("Unknown subcommand"),
    }
}
