use keystore::{EncryptedArchiveName, EncryptedArchive, EncryptedBlock, BlockId};
use backend::Backend;
use acd;
use std::path::Path;
use std::fs::File;
use std::io::Read;
use rustc_serialize::json;
use std::str::FromStr;
use error::*;


pub struct AcdBackend {
    acd: acd::Client,
}

impl AcdBackend {
    pub fn new() -> Result<AcdBackend> {
        #[derive(RustcDecodable)]
        struct SecurityProfile {
            client_id: String,
            client_secret: String,
        }

        let security_profile: SecurityProfile = {
            let mut f = try!(File::open(".config/acd.security_profile.json"));
            let mut s = String::new();
            try!(f.read_to_string(&mut s));
            try!(json::decode(&s))
        };

        let acd = try!(acd::Client::new(&security_profile.client_id,
                                        &security_profile.client_secret,
                                        ".config",
                                        1000000));

        Ok(AcdBackend { acd: acd })
    }
}

impl Backend for AcdBackend {
    fn block_exists(&mut self, id: &BlockId) -> Result<bool> {
        let block_id = id.to_string();
        let dir1 = &block_id[0..2];
        let dir2 = &block_id[2..4];

        if let Some(_) = try!(self.acd.find_path(None,
                                                 &("/gbackup/blocks/".to_owned() + &dir1 + "/" +
                                                   &dir2 +
                                                   "/" +
                                                   &block_id))) {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn store_block(&mut self,
                   id: &BlockId,
                   &EncryptedBlock(ref data): &EncryptedBlock)
                   -> Result<()> {
        let block_id = id.to_string();
        let path = Path::new("/gbackup/blocks/")
            .join(&block_id[0..2])
            .join(&block_id[2..4]);

        let acd_id = try!(self.acd.mkdir_all(None, path));

        if let Some(_) = try!(self.acd.find_path(Some(&acd_id), &block_id)) {
            return Ok(());
        }

        match self.acd.upload(Some(&acd_id), &block_id, data, None) {
            Ok(_) => Ok(()),
            Err(acd::Error::NodeExists) => Ok(()),
            Err(err) => Err(Error::from(err)),
        }
    }

    fn fetch_block(&mut self, id: &BlockId) -> Result<EncryptedBlock> {
        let block_id = id.to_string();
        let dir1 = &block_id[0..2];
        let dir2 = &block_id[2..4];

        let acd_id = match try!(self.acd.find_path(None,
                                                   &("/gbackup/blocks/".to_owned() + dir1 + "/" +
                                                     dir2 +
                                                     "/" +
                                                     &block_id))) {
            Some(id) => id,
            None => return Err(Error::BlockNotFound),
        };
        let buffer = try!(self.acd.download(&acd_id));

        Ok(EncryptedBlock(buffer))
    }

    fn fetch_archive(&mut self, name: &EncryptedArchiveName) -> Result<EncryptedArchive> {
        let acd_id = match try!(self.acd
            .find_path(None, Path::new("/gbackup/archives/").join(name.to_string()))) {
            Some(id) => id,
            None => return Err(Error::ArchiveNotFound),
        };
        let buffer = try!(self.acd.download(&acd_id));

        Ok(EncryptedArchive(buffer))
    }

    fn store_archive(&mut self,
                     name: &EncryptedArchiveName,
                     &EncryptedArchive(ref payload): &EncryptedArchive)
                     -> Result<()> {
        let archives_id = try!(self.acd.mkdir_all(None, "/gbackup/archives/"));

        try!(self.acd.upload(Some(&archives_id), &name.to_string(), payload, None));
        Ok(())
    }

    fn list_archives(&mut self) -> Result<Vec<EncryptedArchiveName>> {
        let archives_id = match try!(self.acd.find_path(None, Path::new("/gbackup/archives"))) {
            Some(archives_id) => archives_id,
            None => return Ok(Vec::new()),
        };
        let mut archives = Vec::new();
        let acd_archive_files = try!(self.acd.ls(&archives_id));

        for acd_file in acd_archive_files {
            let encrypted_archive_name = match EncryptedArchiveName::from_str(&acd_file.0) {
                Ok(name) => name,
                Err(_) => return Err(Error::InvalidArchiveName),
            };
            archives.push(encrypted_archive_name);
        }

        Ok(archives)
    }
}
