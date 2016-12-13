use std::env::home_dir;
use std::fs::File;
use std::io::Read;
use std::str::FromStr;
use std::path::PathBuf;
use backend::Backend;
use ceph_rust::rados::{rados_t, rados_ioctx_t};
use ceph_rust::ceph::{get_rados_ioctx, connect_to_ceph, Pool, rados_object_stat,
                      destroy_rados_ioctx, disconnect_from_ceph, rados_object_read,
                      rados_list_pool_objects, rados_object_write_full, rados_set_namespace};
use clap::ArgMatches;
use error::*;
use keystore::{EncryptedArchiveName, EncryptedArchive, EncryptedBlock, BlockId};
use rustc_serialize::json;

/// Backup to a Ceph cluster
pub struct CephBackend {
    cluster_handle: rados_t,
    ioctx: rados_ioctx_t,
    /// where to store the data chunks
    data_pool: String,
}

#[derive(RustcDecodable)]
struct CephConfig {
    /// The location of the ceph.conf file
    config_file: String,
    /// The cephx user to connect to the Ceph service with
    user_id: String,
    /// Where to store the data
    data_pool: String,
}

impl CephBackend {
    pub fn new(config_dir: Option<PathBuf>) -> Result<CephBackend> {
        let ceph_config: CephConfig = match config_dir {
            Some(config) => {
                info!("Reading ceph config file: {}/{}",
                      config.display(),
                      "ceph.json");
                let mut f = try!(File::open(config.join("ceph.json")));
                let mut s = String::new();
                try!(f.read_to_string(&mut s));
                try!(json::decode(&s))

            }
            None => {
                info!("Reading ceph config file: {}/{}",
                      home_dir().unwrap().to_string_lossy(),
                      ".config/ceph.json");
                let mut f = try!(File::open(format!("{}/{}",
                                                    home_dir().unwrap().to_string_lossy(),
                                                    ".config/ceph.json")));
                let mut s = String::new();
                try!(f.read_to_string(&mut s));
                try!(json::decode(&s))
            }
        };
        info!("Connecting to Ceph");
        let cluster_handle = try!(connect_to_ceph(&ceph_config.user_id, &ceph_config.config_file));
        info!("Getting rados ioctx");
        let ioctx = try!(get_rados_ioctx(cluster_handle, &ceph_config.data_pool));
        info!("Connected to ceph");
        Ok(CephBackend {
            cluster_handle: cluster_handle,
            ioctx: ioctx,
            data_pool: ceph_config.data_pool,
        })
    }
}
impl Drop for CephBackend {
    fn drop(&mut self) {
        destroy_rados_ioctx(self.ioctx);
        disconnect_from_ceph(self.cluster_handle);
    }
}

impl Backend for CephBackend {
    fn block_exists(&mut self, id: &BlockId) -> Result<bool> {
        let block_id = id.to_string();
        match rados_object_stat(self.ioctx, &block_id) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn store_block(&mut self,
                   id: &BlockId,
                   &EncryptedBlock(ref data): &EncryptedBlock)
                   -> Result<()> {
        let block_id = id.to_string();
        try!(rados_object_write_full(self.ioctx, &block_id, data));
        Ok(())
    }

    fn fetch_block(&mut self, id: &BlockId) -> Result<EncryptedBlock> {
        let block_id = id.to_string();

        // 2MB buffer.  Should be enough for any chunk because they're broken into 1MB
        let mut ciphertext = Vec::<u8>::with_capacity(1024 * 1024 * 2);
        let bytes_read = try!(rados_object_read(self.ioctx, &block_id, &mut ciphertext, 0));
        debug!("Read {} bytes from ceph for fetch_block", bytes_read);

        Ok(EncryptedBlock(ciphertext))
    }

    fn fetch_archive(&mut self, name: &EncryptedArchiveName) -> Result<EncryptedArchive> {
        let mut ciphertext = Vec::<u8>::with_capacity(1024 * 1024);
        let ioctx = try!(get_rados_ioctx(self.cluster_handle, &self.data_pool));
        try!(rados_set_namespace(ioctx, "metadata"));
        let bytes_read = try!(rados_object_read(ioctx, &name.to_string(), &mut ciphertext, 0));
        debug!("Read {} bytes from ceph for fetch_archive", bytes_read);
        destroy_rados_ioctx(ioctx);

        Ok(EncryptedArchive(ciphertext))
    }

    fn store_archive(&mut self,
                     name: &EncryptedArchiveName,
                     &EncryptedArchive(ref payload): &EncryptedArchive)
                     -> Result<()> {
        let ioctx = try!(get_rados_ioctx(self.cluster_handle, &self.data_pool));
        try!(rados_set_namespace(ioctx, "metadata"));

        try!(rados_object_write_full(ioctx, &name.to_string(), payload));
        destroy_rados_ioctx(ioctx);
        Ok(())
    }

    fn list_archives(&mut self) -> Result<Vec<EncryptedArchiveName>> {
        let mut archives = Vec::new();
        let ioctx = try!(get_rados_ioctx(self.cluster_handle, &self.data_pool));
        try!(rados_set_namespace(ioctx, "metadata"));
        let pool_list_ctx = try!(rados_list_pool_objects(ioctx));
        let pool = Pool { ctx: pool_list_ctx };

        for ceph_object in pool {
            // object item name
            let encrypted_archive_name = match EncryptedArchiveName::from_str(&ceph_object.name) {
                Ok(name) => name,
                Err(_) => return Err(Error::InvalidArchiveName),
            };
            archives.push(encrypted_archive_name);
        }
        destroy_rados_ioctx(ioctx);

        Ok(archives)
    }
}
