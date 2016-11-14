use std::path::Path;
use std::str::FromStr;

use backend::Backend;
use ceph_rust::rados::rados_t;
use ceph_rust::ceph::{get_rados_ioctx, connect_to_ceph, Pool, rados_object_stat,
                      rados_object_read, rados_list_pool_objects, rados_object_write_full};

use error::*;
use keystore::{EncryptedArchiveName, EncryptedArchive, EncryptedBlock, BlockId};

/// Backup to a Ceph cluster
pub struct CephBackend {
    cluster_handle: rados_t,
    /// where to store the data chunks
    data_pool: String,
    /// Where to store the archive metadata
    metadata_pool: String,
}

impl CephBackend {
    pub fn new<P: AsRef<Path>>(ceph_conf: P) -> Result<CephBackend> {
        let cluster_handle = try!(connect_to_ceph("admin", &ceph_conf.as_ref().to_string_lossy()));
        Ok(CephBackend {
            cluster_handle: cluster_handle,
            data_pool: String::from("data"),
            metadata_pool: String::from("metadata"),
        })
    }
}

impl Backend for CephBackend {
    fn block_exists(&mut self, id: &BlockId) -> Result<bool> {
        let block_id = id.to_string();
        let rados_ctx = try!(get_rados_ioctx(self.cluster_handle, &self.data_pool));
        match rados_object_stat(rados_ctx, &block_id) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn store_block(&mut self,
                   id: &BlockId,
                   &EncryptedBlock(ref data): &EncryptedBlock)
                   -> Result<()> {
        let block_id = id.to_string();
        let rados_ctx = try!(get_rados_ioctx(self.cluster_handle, &self.data_pool));

        try!(rados_object_write_full(rados_ctx, &block_id, data));
        Ok(())
    }

    fn fetch_block(&mut self, id: &BlockId) -> Result<EncryptedBlock> {
        let block_id = id.to_string();
        let rados_ctx = try!(get_rados_ioctx(self.cluster_handle, &self.data_pool));

        let mut ciphertext = Vec::<u8>::with_capacity(1024 * 1024);
        try!(rados_object_read(rados_ctx, &block_id, &mut ciphertext, 0));

        Ok(EncryptedBlock(ciphertext))
    }

    fn fetch_archive(&mut self, name: &EncryptedArchiveName) -> Result<EncryptedArchive> {
        let rados_ctx = try!(get_rados_ioctx(self.cluster_handle, &self.metadata_pool));

        let mut ciphertext = Vec::<u8>::with_capacity(1024 * 1024);
        try!(rados_object_read(rados_ctx, &name.to_string(), &mut ciphertext, 0));

        Ok(EncryptedArchive(ciphertext))
    }

    fn store_archive(&mut self,
                     name: &EncryptedArchiveName,
                     &EncryptedArchive(ref payload): &EncryptedArchive)
                     -> Result<()> {

        let rados_ctx = try!(get_rados_ioctx(self.cluster_handle, &self.metadata_pool));
        try!(rados_object_write_full(rados_ctx, &name.to_string(), payload));
        Ok(())
    }

    fn list_archives(&mut self) -> Result<Vec<EncryptedArchiveName>> {
        let mut archives = Vec::new();
        let rados_ctx = try!(get_rados_ioctx(self.cluster_handle, &self.metadata_pool));
        let pool_list_ctx = try!(rados_list_pool_objects(rados_ctx));
        let pool = Pool { ctx: pool_list_ctx };

        for ceph_object in pool {
            // object item name
            let encrypted_archive_name = match EncryptedArchiveName::from_str(&ceph_object.name) {
                Ok(name) => name,
                Err(_) => return Err(Error::InvalidArchiveName),
            };
            archives.push(encrypted_archive_name);
        }

        Ok(archives)
    }
}
