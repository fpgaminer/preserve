use keystore::{EncryptedArchiveName, EncryptedArchive, EncryptedBlock, BlockId};
use backend::Backend;
use acd::{self, AmazonCloudDrive};
use std::path::Path;


pub struct AcdBackend {
	acd: AmazonCloudDrive,
}

impl AcdBackend {
	pub fn new() -> AcdBackend {
		let acd = AmazonCloudDrive::new().unwrap();

		AcdBackend {
			acd: acd,
		}
	}
}

impl Backend for AcdBackend {
	fn block_exists(&mut self, id: &BlockId) -> bool {
		let block_id = id.to_string();
		let dir1 = &block_id[0..2];
		let dir2 = &block_id[2..4];

		if let Some(_) = self.acd.find_path(None, &("/gbackup/blocks/".to_owned() + &dir1 + "/" + &dir2 + "/" + &block_id)).unwrap() {
			true
		} else {
			false
		}
	}

	fn store_block(&mut self, id: &BlockId, &EncryptedBlock(ref data): &EncryptedBlock) {
		let block_id = id.to_string();
		let path = Path::new("/gbackup/blocks/")
			.join(&block_id[0..2])
			.join(&block_id[2..4]);

		let acd_id = self.acd.mkdir_all(None, path).unwrap();

		if let Some(_) = self.acd.find_path(Some(&acd_id), &block_id).unwrap() {
			return;
		}

		match self.acd.upload(Some(&acd_id), &block_id, data, None) {
			Ok(_) => (),
			Err(acd::error::Error::NodeExists) => (),
			Err(err) => panic!("Error while uploading: {:?}", err),
		}
	}

	fn fetch_block(&mut self, id: &BlockId) -> EncryptedBlock {
		let block_id = id.to_string();
		let dir1 = &block_id[0..2];
		let dir2 = &block_id[2..4];

		let acd_id = self.acd.find_path(None, &("/gbackup/blocks/".to_owned() + dir1 + "/" + dir2 + "/" + &block_id)).unwrap().unwrap();
		let buffer = self.acd.download(&acd_id).unwrap();

		EncryptedBlock(buffer)
	}

	fn fetch_archive(&mut self, name: &EncryptedArchiveName) -> EncryptedArchive {
		let acd_id = self.acd.find_path(None, Path::new("/gbackup/archives/").join(name.to_string())).unwrap().unwrap();
		let buffer = self.acd.download(&acd_id).unwrap();

		EncryptedArchive(buffer)
	}

	fn store_archive(&mut self, name: &EncryptedArchiveName, &EncryptedArchive(ref payload): &EncryptedArchive) {
		let archives_id = self.acd.mkdir_all(None, "/gbackup/archives/").unwrap();

		self.acd.upload(Some(&archives_id), &name.to_string(), payload, None).unwrap();
	}

	fn list_archives(&mut self) -> Vec<EncryptedArchiveName> {
		// TODO
		panic!("Not implemented");
	}
}
