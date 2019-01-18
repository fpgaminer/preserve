use keystore::{EncryptedArchiveName, EncryptedArchive, EncryptedBlock, BlockId};
use error::*;
use url::Url;

pub mod file;

pub use backend::file::FileBackend;


pub trait Backend {
	fn block_exists(&mut self, id: &BlockId) -> Result<bool>;
	fn store_block(&mut self, id: &BlockId, data: &EncryptedBlock) -> Result<()>;
	fn fetch_block(&mut self, id: &BlockId) -> Result<EncryptedBlock>;

	fn store_archive(&mut self, name: &EncryptedArchiveName, data: &EncryptedArchive) -> Result<()>;
	fn fetch_archive(&mut self, name: &EncryptedArchiveName) -> Result<EncryptedArchive>;
	fn list_archives(&mut self) -> Result<Vec<EncryptedArchiveName>>;
}


/// Given a backend path, return a Box'd Backend.
pub fn backend_from_backend_path(path: &str) -> Result<Box<Backend>> {
	let url = try!(Url::parse(path).map_err(|_| Error::BadBackendPath("Given backend path could not be understood.".to_string())));

	let backend: Box<Backend> = match url.scheme() {
		"file" => Box::new(FileBackend::new(url.path())),
		e => return Err(Error::BadBackendPath(format!("Unknown backend: {}", e))),
	};

	Ok(backend)
}
