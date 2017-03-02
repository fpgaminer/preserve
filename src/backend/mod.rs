use std::path::PathBuf;

use keystore::{EncryptedArchiveName, EncryptedArchive, EncryptedBlock, BlockId};
use error::*;
use url::Url;

pub mod acd;
#[cfg(feature = "ceph")]
pub mod ceph;
pub mod file;
#[cfg(feature = "gluster")]
pub mod gluster;

pub use backend::acd::AcdBackend;
#[cfg(feature = "ceph")]
pub use backend::ceph::CephBackend;
pub use backend::file::FileBackend;
#[cfg(feature = "gluster")]
pub use backend::gluster::GlusterBackend;


pub trait Backend {
    fn block_exists(&mut self, id: &BlockId) -> Result<bool>;
    fn store_block(&mut self, id: &BlockId, data: &EncryptedBlock) -> Result<()>;
    fn fetch_block(&mut self, id: &BlockId) -> Result<EncryptedBlock>;

    fn store_archive(&mut self,
                     name: &EncryptedArchiveName,
                     data: &EncryptedArchive)
                     -> Result<()>;
    fn fetch_archive(&mut self, name: &EncryptedArchiveName) -> Result<EncryptedArchive>;
    fn list_archives(&mut self) -> Result<Vec<EncryptedArchiveName>>;
}


/// Given a backend path, return a Box'd Backend.
pub fn backend_from_backend_path(path: &str, config_dir: Option<PathBuf>) -> Result<Box<Backend>> {
    let url = try!(Url::parse(path).map_err(|_| {
        Error::BadBackendPath("Given backend path could not be understood.".to_string())
    }));

    let backend: Box<Backend> = match url.scheme() {
        "acd" => Box::new(try!(AcdBackend::new(config_dir))),
        #[cfg(feature = "ceph")]
        "ceph" => Box::new(try!(CephBackend::new(config_dir))),
        "file" => Box::new(FileBackend::new(url.path())),
        #[cfg(feature = "gluster")]
        "gluster" => Box::new(try!(GlusterBackend::new(config_dir))),
        e => return Err(Error::BadBackendPath(format!("Unknown backend: {}", e))),
    };

    Ok(backend)
}
