use keystore::{EncryptedArchiveName, EncryptedArchive, EncryptedBlock, BlockId};
use backend::Backend;
use acd;
use std::path::Path;
use std::fs::File;
use std::io::Read;
use rustc_serialize::json;


pub struct AcdBackend {
	acd: acd::Client,
}

impl AcdBackend {
	pub fn new() -> AcdBackend {
		#[derive(RustcDecodable)]
		struct SecurityProfile {
			client_id: String,
			client_secret: String,
		}

		let security_profile: SecurityProfile = {
			let mut f = File::open(".config/acd.security_profile.json").unwrap();
			let mut s = String::new();
			f.read_to_string(&mut s).unwrap();
			json::decode(&s).unwrap()
		};

		let acd = acd::Client::new(&security_profile.client_id, &security_profile.client_secret, ".config").unwrap();

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
			Err(acd::Error::NodeExists) => (),
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
