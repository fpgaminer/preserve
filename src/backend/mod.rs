use keystore::{EncryptedArchiveName, EncryptedArchive, EncryptedBlock, BlockId};

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
