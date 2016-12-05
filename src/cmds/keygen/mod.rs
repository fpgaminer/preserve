use std::env::home_dir;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Read, Write};

use clap::ArgMatches;
use error::*;
use keystore::KeyStore;
use rustc_serialize::json;
use rustc_serialize::base64::{ToBase64, STANDARD};
use vault::Client;

#[derive(RustcDecodable)]
pub struct VaultConfig {
    /// The url location of a vault writable host
    pub host: String,
    /// The token that can be used to write to vault
    pub token: String,
}

fn save_keys_to_vault(buffer: &str) -> Result<()> {
    let vault_config: VaultConfig = {
        info!("Reading vault config file: {}/{}",
              home_dir().unwrap().to_string_lossy(),
              ".config/vault.json");
        let mut f = try!(File::open(format!("{}/{}",
                                            home_dir().unwrap().to_string_lossy(),
                                            ".config/vault.json")));
        let mut s = String::new();
        try!(f.read_to_string(&mut s));
        try!(json::decode(&s))
    };
    info!("Connecting to vault");
    let client = try!(Client::new(&vault_config.host, &vault_config.token));
    info!("Storing backup_key in vault");
    let encoded = buffer.as_bytes().to_base64(STANDARD);
    try!(client.set_secret("backup_key", &encoded));
    Ok(())
}

#[test]
fn test_save_keys_to_vault() {
    save_keys_to_vault("123").unwrap();
    let vault_config: VaultConfig = {
        let mut f = File::open(format!("{}/{}",
                                       home_dir().unwrap().to_string_lossy(),
                                       ".config/vault.json"))
            .unwrap();
        let mut s = String::new();
        f.read_to_string(&mut s).unwrap();
        json::decode(&s).unwrap()
    };
    let client = Client::new(&vault_config.host, &vault_config.token).unwrap();
    client.delete_secret("backup_key").unwrap()
}

pub fn execute(args: &ArgMatches) {
    if args.is_present("vault") {
        // Save the keyfile to vault
        // Create a new keystore
        let keystore = KeyStore::new();

        match save_keys_to_vault(&keystore.as_pretty_json()) {
            Ok(_) => {
                info!("Backup key saved to vault successfully");
            }
            Err(e) => {
                error!("Saving keys to vault failed with error: {}", e);
                return;
            }
        };
    } else {
        // Create a new keystore
        let keystore = KeyStore::new();

        // Open output file/stdout for writing
        let file: Box<Write> = match args.value_of("keyfile") {
            Some(path) => {
                // Won't overwrite existing file
                let file = match OpenOptions::new().write(true).create_new(true).open(path) {
                    Ok(f) => f,
                    Err(e) => {
                        if e.kind() == io::ErrorKind::AlreadyExists {
                            error!("'{}' already exists.", path);
                            return;
                        } else {
                            error!("Could not open '{}' for writing: {}", path, e);
                            return;
                        }
                    }
                };
                Box::new(file)
            }
            None => Box::new(io::stdout()),
        };
        let mut writer = BufWriter::new(file);

        // Save the keystore to the destination (file/stdout)
        match keystore.save(&mut writer) {
            Ok(_) => {}
            Err(err) => {
                error!("Could not write to keyfile: {}", err);
                return;
            }
        }
    }
}
