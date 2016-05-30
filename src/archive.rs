use keystore::{KeyStore, EncryptedArchiveName, EncryptedArchive};
use lzma;
use rustc_serialize::json;


#[derive(RustcDecodable, RustcEncodable, Clone)]
pub struct File {
	/// Path, relative to the archive
	pub path: String,
	/// true if this is a directory, false if it's a file
	pub is_dir: bool,
	/// If specified, then this File is a symlink with the link path specified
	pub symlink: Option<String>,
	/// If specified, this is a unique id for identifying all the links to a hardlink
	pub hardlink_id: Option<u64>,
	/// File mode (right now, it should just be permissions, since only directories and regular files are archived)
	pub mode: u32,
	/// Modification time (combine with mtime_nsec)
	pub mtime: i64,
	pub mtime_nsec: i64,
	/// User id
	pub uid: u32,
	/// Group id
	pub gid: u32,
	/// File size
	pub size: u64,
	/// Data blocks (list of block secrets)
	pub blocks: Vec<String>,
}


/// An archive has some metadata, but it is primarily just a list of files.
/// While the original filesystem was likely a file tree, we squash it to a simple list, since dealing
/// with it as a tree would require lots of extra, nasty code.
/// The list is ordered such that folders are listed before the children inside of them, making restore
/// easy.
#[derive(RustcDecodable, RustcEncodable)]
pub struct Archive {
	pub version: u32,
	pub name: String,
	pub original_path: String,
	pub files: Vec<File>,
}


impl Archive {
	pub fn encrypt(self, keystore: &KeyStore) -> (EncryptedArchiveName, EncryptedArchive) {
		let encrypted_name = keystore.encrypt_archive_name(&self.name);

		let encoded = json::as_json(&self);
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
