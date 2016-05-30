use keystore::{EncryptedArchiveName, EncryptedArchive, EncryptedBlock, BlockId};
use error::*;
use url::Url;

pub mod file;
pub mod acd;

pub use backend::file::FileBackend;
pub use backend::acd::AcdBackend;


pub trait Backend {
	fn block_exists(&mut self, id: &BlockId) -> bool;
	fn store_block(&mut self, id: &BlockId, data: &EncryptedBlock);
	fn fetch_block(&mut self, id: &BlockId) -> EncryptedBlock;

	fn store_archive(&mut self, name: &EncryptedArchiveName, data: &EncryptedArchive);
	fn fetch_archive(&mut self, name: &EncryptedArchiveName) -> EncryptedArchive;
	fn list_archives(&mut self) -> Vec<EncryptedArchiveName>;
}


/// Given a backend path, return a Box'd Backend.
pub fn backend_from_backend_path(path: &str) -> Result<Box<Backend>> {
	let url = try!(Url::parse(path).map_err(|_| Error::BadBackendPath("Given backend path could not be understood.".to_string())));

	let backend: Box<Backend> = match url.scheme() {
		"acd" => Box::new(AcdBackend::new()),
		"file" => Box::new(FileBackend::new(url.path())),
		e => return Err(Error::BadBackendPath(format!("Unknown backend: {}", e))),
	};

	Ok(backend)
}
