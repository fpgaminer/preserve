use keystore::{KeyStore, EncryptedArchiveName, EncryptedArchive};
use lzma;
use rustc_serialize::json;


#[derive(RustcDecodable, RustcEncodable)]
pub struct File {
	pub path: String,
	pub is_dir: bool,
	pub mode: u32,
	pub mtime: i64,
	pub mtime_nsec: i64,
	pub uid: u32,
	pub gid: u32,
	pub size: u64,
	pub children: Vec<File>,
	pub blocks: Vec<String>,
}


#[derive(RustcDecodable, RustcEncodable)]
pub struct Archive {
	pub version: u32,
	pub name: String,
	pub files: Vec<File>,
}


impl Archive {
	pub fn encrypt(self, keystore: &KeyStore) -> (EncryptedArchiveName, EncryptedArchive) {
		let encrypted_name = keystore.encrypt_archive_name(&self.name);

		let encoded = json::as_pretty_json(&self);
		let compressed = lzma::compress(encoded.to_string().as_bytes(), 9 | lzma::EXTREME_PRESET).unwrap();
		let encrypted_archive = keystore.encrypt_archive(&encrypted_name, &compressed);

		(encrypted_name, encrypted_archive)
	}

	pub fn decrypt(encrypted_name: &EncryptedArchiveName, encrypted_archive: &EncryptedArchive, keystore: &KeyStore) -> Archive {
		let compressed = keystore.decrypt_archive(encrypted_name, encrypted_archive);

		let data = String::from_utf8(lzma::decompress(&compressed).unwrap()).unwrap();
		json::decode(&data).unwrap()
	}
}
