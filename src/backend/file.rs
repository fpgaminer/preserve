use backend::Backend;
use keystore::{EncryptedArchiveName, EncryptedArchive, EncryptedBlock, BlockId};
use std::path::{Path, PathBuf};
use std::io::{BufReader, Read, Write};
use std::fs::{self, OpenOptions};
use rand::{Rng, OsRng};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::str::FromStr;


pub struct FileBackend {
	backup_dir: PathBuf,
}

impl FileBackend {
	pub fn new<P: AsRef<Path>>(backup_dir: P) -> FileBackend {
		FileBackend {
			backup_dir: backup_dir.as_ref().to_path_buf(),
		}
	}

	fn safely_write_file<P: AsRef<Path>>(&self, destination: P, data: &[u8]) {
		// First, write to a temporary file.
		let temppath = {
			let mut rng = OsRng::new().unwrap();
			let tempname: String = rng.gen_ascii_chars().take(25).collect();
			let temppath = self.backup_dir.join("temp");
			fs::create_dir_all(&temppath).unwrap_or(());
			temppath.join(tempname)
		};

		{
			let mut file = OpenOptions::new().write(true).create(true).open(&temppath).unwrap();

			// TODO: Should we use BufWriter here?  Profile
			file.write_all(data).unwrap();
		}

		// Archives and Blocks should be stored as world readonly
		fs::set_permissions(&temppath, PermissionsExt::from_mode(0o444)).unwrap();

		assert_eq!(temppath.metadata().unwrap().dev(), destination.as_ref().parent().unwrap().metadata().unwrap().dev());

		// Then move the file to its final destination.  This avoids any truncation in case of early
		// termination/crash.
		fs::rename(temppath, destination).unwrap();
	}
}

impl Backend for FileBackend {
	fn block_exists(&mut self, id: &BlockId) -> bool {
		let block_id = id.to_string();
		let dir1 = &block_id[0..2];
		let dir2 = &block_id[2..4];

		let path = self.backup_dir.join("blocks").join(dir1).join(dir2).join(&block_id);

		path.exists()
	}

	fn store_block(&mut self, id: &BlockId, &EncryptedBlock(ref data): &EncryptedBlock) {
		let block_id = id.to_string();
		let dir1 = &block_id[0..2];
		let dir2 = &block_id[2..4];

		let path = {
			let path = self.backup_dir.join("blocks").join(dir1).join(dir2);
			fs::create_dir_all(&path).unwrap_or(());
			path.join(&block_id)
		};

		if path.exists() {
			return;
		}

		self.safely_write_file(path, data);
	}

	fn fetch_block(&mut self, id: &BlockId) -> EncryptedBlock {
		let block_id = id.to_string();
		let dir1 = &block_id[0..2];
		let dir2 = &block_id[2..4];

		let path = self.backup_dir.join("blocks").join(dir1).join(dir2).join(&block_id);
		let mut file = fs::File::open(path).unwrap();

		let mut ciphertext = Vec::<u8>::new();

		file.read_to_end(&mut ciphertext).unwrap();

		EncryptedBlock(ciphertext)
	}

	fn fetch_archive(&mut self, name: &EncryptedArchiveName) -> EncryptedArchive {
		let path = self.backup_dir.join("archives").join(name.to_string());

		let mut buffer = vec![0u8; 0];
		let mut reader = BufReader::new(fs::File::open(path).unwrap());

		reader.read_to_end(&mut buffer).unwrap();
		EncryptedArchive(buffer)
	}

	fn store_archive(&mut self, name: &EncryptedArchiveName, &EncryptedArchive(ref payload): &EncryptedArchive) {
		let path = {
			let path = self.backup_dir.join("archives");
			fs::create_dir_all(&path).unwrap_or(());
			path.join(name.to_string())
		};

		if path.exists() {
			panic!("Archive already exists");
		}

		self.safely_write_file(path, payload);
	}

	fn list_archives(&mut self) -> Vec<EncryptedArchiveName> {
		let mut archives = Vec::new();

		for entry in fs::read_dir(self.backup_dir.join("archives")).unwrap() {
			let entry = entry.unwrap();
			let encrypted_archive_name = EncryptedArchiveName::from_str(entry.file_name().to_str().unwrap()).unwrap();

			archives.push(encrypted_archive_name);
		}

		archives
	}
}
