use keystore::{KeyStore, Secret};
use std::fs;
use std::io::{Read, BufReader};
use block::BlockStore;
use std::path::{Path, PathBuf};
use std::os::unix::fs::MetadataExt;
use rustc_serialize::hex::{ToHex, FromHex};
use std::string::ToString;
use backend::{AcdBackend, FileBackend, Backend};
use archive::{Archive, File};
use rusqlite;
use std::collections::{HashSet, HashMap};
use std::env;
use clap::ArgMatches;


pub fn execute(args: &ArgMatches) {
	let mut config = Config::default();
	let backup_name = args.value_of("NAME").unwrap();
	let target_directory = Path::new(args.value_of("PATH").unwrap()).canonicalize().unwrap();

	config.dereference_symlinks = args.is_present("dereference");

	let mut reader = BufReader::new(fs::File::open(args.value_of("keyfile").unwrap()).unwrap());
	let keystore = KeyStore::load(&mut reader);
	let block_store = BlockStore::new(&keystore);
	let mut backend: Box<Backend> = {
		match &args.value_of("backend").unwrap()[..] {
			"acd" => Box::new(AcdBackend::new()),
			"file" => Box::new(FileBackend::new(args.value_of("backend-path").unwrap())),
			x => panic!("Unknown backend {}", x),
		}
	};

	// Build archive
	let archive = {
		let mut builder = ArchiveBuilder::new(config, &target_directory, &mut *backend, &block_store);
		info!("Gathering list of files...");
		builder.walk();
		info!("Reading files...");
		builder.read_files();
		builder.warn_about_missing_symlinks();
		builder.warn_about_missing_hardlinks();

		builder.create_archive(&backup_name)
	};

	info!("Writing archive...");
	let (encrypted_archive_name, encrypted_archive) = archive.encrypt(&keystore);
	backend.store_archive(&encrypted_archive_name, &encrypted_archive);
	info!("Done");
}


#[derive(Default)]
struct Config {
	/// If true, follow symlinks.
	/// If false, symlinks are saved as symlinks in the archive.
	pub dereference_symlinks: bool,
	/// If true, we will skip all files/directories that reside on other filesystems.
	/// This is on by default, and useful to ignore /dev and others like it when backing up /.
	pub one_file_system: bool,
}

/// Used to uniquely identify a file during backup creation, so we can
/// easily skip certain files (like our cache databases).
#[derive(Eq, PartialEq, Hash)]
struct FileIdentifier {
	devid: u64,
	inode: u64,
}

struct HardLink {
	/// How many links exist to this inode, on the user's system.
	expected_links: u64,
	/// We assign a unique id to each hardlink during backup creation,
	/// which, in the archive, is then assigned to each file involved in the hardlink.
	/// We could use (devid, inode), but that seems wasteful and perhaps non-portable.
	/// So we'll just assign our own id, unique within the archive, using a simple counter.
	id: u64,
	/// Used for error reporting; just one of the paths that points to this inode.
	example_path: PathBuf,
}

// Wrap File so we can keep track of a few extra things while building the archive
struct ArchiveBuilderFile {
	file: File,
	missing: bool,
	canonical_path: Option<PathBuf>,
}

struct ArchiveBuilder<'a> {
	config: Config,
	base_path: PathBuf,
	hardlink_map: HashMap<FileIdentifier, HardLink>,
	last_hardlink_id: u64,
	total_size: u64,
	ignore_list: HashSet<FileIdentifier>,
	files: Vec<ArchiveBuilderFile>,
	backend: &'a mut Backend,
	block_store: &'a BlockStore<'a>,
}

impl<'a> ArchiveBuilder<'a> {
	fn new<P: AsRef<Path>>(config: Config, base_path: P, backend: &'a mut Backend, block_store: &'a BlockStore) -> ArchiveBuilder<'a> {
		let base_path = if base_path.as_ref().is_relative() {
			env::current_dir().unwrap().join(base_path)
		} else {
			PathBuf::from(base_path.as_ref())
		};

		ArchiveBuilder {
			config: config,
			base_path: base_path,
			hardlink_map: HashMap::new(),
			total_size: 0,
			last_hardlink_id: 0,
			ignore_list: HashSet::new(),
			files: Vec::new(),
			backend: backend,
			block_store: block_store,
		}
	}

	fn open_cache_db(&self) -> rusqlite::Connection {
		let db = rusqlite::Connection::open("cache.sqlite").unwrap();

		db.execute("CREATE TABLE IF NOT EXISTS mtime_cache (
			path TEXT NOT NULL,
			mtime INTEGER NOT NULL,
			mtime_nsec INTEGER NOT NULL,
			size INTEGER NOT NULL,
			blocks TEXT NOT NULL
		)", &[]).unwrap();

		db.execute("CREATE INDEX IF NOT EXISTS idx_mtime_cache_path_mtime_size ON mtime_cache (path, mtime, mtime_nsec, size);", &[]).unwrap();
		db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_mtime_cache_path ON mtime_cache (path);", &[]).unwrap();

		db
	}

	// Walk the file tree from self.base_path, gathering metadata about all the files
	fn walk(&mut self) {
		self.files = Vec::new();
		self.total_size = 0;

		let base_path = self.base_path.clone();
		let base_path_metadata = self.base_path.metadata().unwrap();
		let current_filesystem = Some(base_path_metadata.dev());
		let mut unscanned_paths: Vec<PathBuf> = Vec::new();

		unscanned_paths.extend(self.list_file_children(&base_path));

		while let Some(path) = unscanned_paths.pop() {
			let file = match self.read_file_metadata(path, current_filesystem) {
				Some(file) => file,
				None => continue,
			};

			if file.file.symlink.is_none() && file.file.is_dir {
				unscanned_paths.extend(self.list_file_children(base_path.join(&file.file.path)));
			}

			self.total_size += file.file.size;
			self.files.push(file);
		}
	}

	fn create_archive(&self, name: &str) -> Archive {
		let mut files = Vec::new();

		for file in &self.files {
			files.push(file.file.clone());
		}

		Archive {
			version: 0x00000001,
			name: name.to_owned(),
			original_path: self.base_path.canonicalize().unwrap().to_str().unwrap().to_string(),
			files: files,
		}
	}

	// Given a path, read the metadata for the file, handle symlinks, hardlinks, etc and return an ArchiveBuilderFile or None if a problem was encountered.
	fn read_file_metadata<P: AsRef<Path>>(&mut self, path: P, current_filesystem: Option<u64>) -> Option<ArchiveBuilderFile> {
		// First, let's see if it's a symlink
		let symlink_metadata = match path.as_ref().symlink_metadata() {
			Ok(metadata) => metadata,
			Err(err) => {
				warn!("Unable to read metadata for '{}'.  It will not be included in the archive.  The following error was received: {}", path.as_ref().display(), err);
				return None
			},
		};

		// Skip files, symlinks, etc that don't reside on the current filesystem we're walking, if --one-file-system is enabled
		if let Some(current_filesystem) = current_filesystem {
			if symlink_metadata.dev() != current_filesystem {
				warn!("'{}' is being skipped because of --one-file-system.", path.as_ref().display());
				return None
			}
		}

		// If we encounter a symlink, and we aren't dereferencing, then we will
		// store information about the symlink, and all metadata will be about
		// the symlink (not the file/folder it points to).
		// If we derference the symlink then all metadata will be about the
		// file/folder the symlink points to.
		let (metadata, symlink_path) = if symlink_metadata.file_type().is_symlink() && !self.config.dereference_symlinks {
			let symlink_path: String = match fs::read_link(path.as_ref()) {
				Ok(symlink_path) => match symlink_path.to_str() {
					Some(symlink_path_str) => symlink_path_str.to_string(),
					None => {
						warn!("Unable to read symlink for '{}' as UTF-8 string.  It will not be included in the archive.", path.as_ref().display());
						return None
					},
				},
				Err(err) => {
					warn!("Unable to read symlink for '{}'.  It will not be included in the archive.  The following error was received: {}", path.as_ref().display(), err);
					return None
				},
			};

			(path.as_ref().symlink_metadata(), Some(symlink_path))
		} else {
			(path.as_ref().metadata(), None)
		};

		let metadata = match metadata {
			Ok(metadata) => metadata,
			Err(err) => {
				warn!("Unable to read metadata for '{}'.  It will not be included in the archive.  The following error was received: {}", path.as_ref().display(), err);
				return None;
			},
		};

		// Skip files, symlinks, etc that don't reside on the current filesystem we're walking, if --one-file-system is enabled
		if let Some(current_filesystem) = current_filesystem {
			if metadata.dev() != current_filesystem {
				warn!("'{}' is being skipped because of --one-file-system.", path.as_ref().display());
				return None
			}
		}

		if self.should_ignore(&metadata) {
			return None;
		}

		// Skip anything that isn't a symlink, regular file, or directory.
		if symlink_path.is_none() && !metadata.is_file() && !metadata.is_dir() {
			warn!("Skipping '{}' because it is not a symlink, directory, or regular file.", path.as_ref().display());
			return None;
		}

		let filesize = if symlink_path.is_none() && metadata.is_file() {
			metadata.len()
		} else {
			0
		};

		let canonical_path = match path.as_ref().canonicalize() {
			Ok(canonical_path) => Some(canonical_path),
			Err(_) => None,
		};

		// The path stored in the archive is relative to the archive's base_path
		let filepath = match path.as_ref().strip_prefix(&self.base_path).unwrap().to_str() {
			Some(filepath) => filepath.to_string(),
			None => {
				warn!("Unable to read path of '{}' as UTF-8 string.  It will not be included in the archive.", path.as_ref().display());
				return None
			}
		};

		// Handle hardlinks
		let hardlink_id = if metadata.nlink() > 1 && !metadata.is_dir() {
			let key = FileIdentifier {
				devid: metadata.dev(),
				inode: metadata.ino(),
			};

			let next_hardlink_id = self.last_hardlink_id;

			let entry = self.hardlink_map.entry(key).or_insert_with(|| {
				HardLink {
					expected_links: metadata.nlink(),
					id: next_hardlink_id,
					example_path: PathBuf::from(path.as_ref()),
				}
			});

			if entry.id == self.last_hardlink_id {
				self.last_hardlink_id += 1;
			}

			Some(entry.id)
		} else {
			None
		};

		Some(ArchiveBuilderFile {
			file: File {
				path: filepath,
				is_dir: metadata.is_dir(),
				symlink: symlink_path,
				hardlink_id: hardlink_id,
				mode: metadata.mode(),
				mtime: metadata.mtime(),
				mtime_nsec: metadata.mtime_nsec(),
				uid: metadata.uid(),
				gid: metadata.gid(),
				size: filesize,
				blocks: Vec::new(),
			},
			missing: false,
			canonical_path: canonical_path,
		})
	}

	/// Assuming that path is a directory, this function returns a list of
	/// all files inside that directory.
	fn list_file_children<P: AsRef<Path>>(&mut self, path: P) -> Vec<PathBuf> {
		let mut children = Vec::new();

		let entries = match path.as_ref().read_dir() {
			Ok(entries) => entries,
			Err(err) => {
				warn!("Unable to read directory '{}'.  The following error was received: {}", path.as_ref().display(), err);
				return Vec::new();
			}
		};

		for entry in entries {
			let entry = match entry {
				Ok(x) => x,
				Err(err) => {
					warn!("Unable to read contents of directory '{}'.  The following error was received: {}", path.as_ref().display(), err);
					return Vec::new();
				}
			};

			children.push(entry.path());
		}

		children
	}

	/// Determine if the given path should be ignored, given the settings.
	fn should_ignore(&self, metadata: &fs::Metadata) -> bool {
		let identifier = FileIdentifier {
			devid: metadata.dev(),
			inode: metadata.ino(),
		};

		if self.ignore_list.contains(&identifier) {
			return true;
		}

		false
	}

	/// Logs warnings about any hardlinks for which we haven't backed up all the links.
	fn warn_about_missing_hardlinks(&self) {
		let mut links_found = HashMap::new();

		for file in &self.files {
			if let Some(hardlink_id) = file.file.hardlink_id {
				*links_found.entry(hardlink_id).or_insert(0) += 1;
			}
		}

		for hardlink in self.hardlink_map.values() {
			match links_found.get(&hardlink.id) {
				Some(links) => {
					if links < &hardlink.expected_links {
						warn!("A hardlink with {} links was included in this backup, but only {} of those links have been included.  One of the links: '{}'", hardlink.expected_links, links, hardlink.example_path.display());
					}
				},
				None => {
					warn!("A hardlink with {} links was supposed to be included in this backup, but none of those links have been included.  One of the links: '{}'", hardlink.expected_links, hardlink.example_path.display());
				}
			}
		}
	}

	/// Logs warnings about any symlinks for which we haven't backed up the file/directory linked.
	fn warn_about_missing_symlinks(&self) {
		// Create a hashset of all archived paths, and a list of all symlinks.
		let mut symlinks = Vec::new();
		let mut paths_archived = HashSet::new();

		for file in &self.files {
			if file.file.symlink.is_some() {
				// Calling canonicalize on the symlink will get us the target file/folder
				let target = match file.canonical_path.clone() {
					Some(target) => target,
					None => {
						warn!("The symlink '{}' was included in the backup, but the file/directory it links to doesn't exist.", file.file.path);
						continue;
					}
				};
				symlinks.push((file.file.path.clone(), target));
			} else {
				paths_archived.insert(file.canonical_path.clone().unwrap());
			}
		}

		// Now we can go through all symlinks and make sure the file/directory they link to exists.
		for (path, symlink) in symlinks {
			if paths_archived.contains(&symlink) {
				continue;
			}

			warn!("The symlink '{}' was included in the backup, but the file/directory it links to, '{}', was not included.", path, symlink.display());
		}
	}

	fn read_files(&mut self) {
		let mut progress = 0;
		let cache_db = self.open_cache_db();

		for file in &mut self.files {
			if file.file.is_dir || file.file.symlink.is_some() {
				continue;
			}

			info!("Reading file: {}", file.file.path);
			match read_file(file, &self.base_path, &cache_db, self.block_store, self.backend, progress, self.total_size) {
				Some(blocks) => file.file.blocks.extend(blocks),
				None => file.missing = true,
			};

			progress += file.file.size;
			info!("Progress: {}MB of {}MB", progress / (1024*1024), self.total_size / (1024*1024));
		}

		self.files.retain(|ref file| !file.missing);
	}
}


fn read_file<P: AsRef<Path>>(file: &mut ArchiveBuilderFile, base_path: P, cache_db: &rusqlite::Connection, block_store: &BlockStore, backend: &mut Backend, progress: u64, total_size: u64) -> Option<Vec<String>> {
	let path = base_path.as_ref().join(&file.file.path);
	let canonical_path = match file.canonical_path.clone() {
		Some(canonical_path) => canonical_path,
		None => {
			warn!("Unable to canonicalize path for '{}'.  It will not be included in the archive.", path.display());
			return None;
		}
	};

	// Check to see if we have this file in the cache
	let result = cache_db.query_row("SELECT blocks FROM mtime_cache WHERE path=? AND mtime=? AND mtime_nsec=? AND size=?", &[&canonical_path.to_str().unwrap().to_owned(), &file.file.mtime, &file.file.mtime_nsec, &(file.file.size as i64)], |row| {
		row.get(0)
	});

	match result {
		Ok(blocks_str) => {
			// The file is cached, but are all the blocks available in the current block store?
			let mut need_reread = false;
			let blocks_str: String = blocks_str;
			let mut blocks = Vec::new();

			if !blocks_str.is_empty() {
				for block in blocks_str.split('\n') {
					let secret = Secret::from_slice(&block.from_hex().unwrap()).unwrap();
					if !block_store.block_exists(&secret, backend) {
						need_reread = true;
						break;
					}
					blocks.push(block.to_owned());
				}
			}

			if !need_reread {
				debug!("Found in mtime cache.");
				return Some(blocks);
			}
		},
		Err(rusqlite::Error::QueryReturnedNoRows) => (),
		Err(err) => panic!("Sqlite error: {}", err),
	};

	// Not cached or missing blocks, so let's actually read the file
	let mut retries = 0;
	loop {
		// Update metadata, in case it changed.
		match path.metadata() {
			Ok(metadata) => {
				file.file.mtime = metadata.mtime();
				file.file.mtime_nsec = metadata.mtime_nsec();
				file.file.size = metadata.size();
				file.file.mode = metadata.mode();
				file.file.uid = metadata.uid();
				file.file.gid = metadata.gid();
			},
			Err(err) => {
				warn!("An error was received while checking the metadata for '{}'.  It will not be included in the archive.  Error message: '{}'.", path.display(), err);
				return None;
			}
		};

		// Read file contents
		let (blocks, should_retry) = read_file_inner(&path, block_store, backend, progress, total_size, file.file.mtime, file.file.mtime_nsec, file.file.size);

		let blocks = match blocks {
			Some(blocks) => blocks,
			None => {
				// Reading failed.  Should we retry?
				if !should_retry {
					return None
				}

				// Reading failed due to the file changing.  Let's retry.
				if retries == 2 {
					warn!("File '{}' keeps changing.  It will not be included in the archive.", path.display());
					return None
				}

				warn!("File changed, restarting from beginning.");
				retries += 1;
				continue;
			},
		};

		let blocks_str = blocks.join("\n");
		cache_db.execute("INSERT OR REPLACE INTO mtime_cache (path, mtime, mtime_nsec, size, blocks) VALUES (?,?,?,?,?)", &[&canonical_path.to_str().unwrap().to_owned(), &file.file.mtime, &file.file.mtime_nsec, &(file.file.size as i64), &blocks_str]).unwrap();

		return Some(blocks);
	}
}


// Used by read_file.  read_file checks the cache, etc.  This will actually read the file into blocks.
// If any file modifications are detected while reading, this function will return (None, true) to indicate the caller that it should retry (if it wishes).
fn read_file_inner<P: AsRef<Path>>(path: P, block_store: &BlockStore, backend: &mut Backend, progress: u64, total_size: u64, expected_mtime: i64, expected_mtime_nsec: i64, expected_size: u64) -> (Option<Vec<String>>, bool) {
	let reader_file = match fs::File::open(&path) {
		Ok(f) => f,
		Err(err) => {
			warn!("Unable to open file '{}'.  The following error was received: {}.  It will not be included in the archive.", path.as_ref().display(), err);
			return (None, false)
		},
	};
	let reader = BufReader::new(&reader_file);
	let reader_ref = reader.get_ref();
	let mut buffer = Vec::<u8>::new();
	let mut total_read = 0;
	let mut blocks = Vec::new();

	loop {
		buffer.clear();
		reader_ref.take(1024*1024).read_to_end(&mut buffer).unwrap();

		// Check for file modification
		match path.as_ref().metadata() {
			Ok(metadata) => {
				if metadata.mtime() != expected_mtime || metadata.mtime_nsec() != expected_mtime_nsec {
					// The file has been modified.  Restart.
					return (None, true);
				}
			},
			Err(err) => {
				warn!("An error was received while checking the metadata for '{}'.  It will not be included in the archive.  Error message: '{}'.", path.as_ref().display(), err);
				return (None, false);
			}
		};

		if buffer.is_empty() {
			break;
		}

		total_read += buffer.len();

		let Secret(secret) = block_store.new_block_from_plaintext(&buffer, backend);
		// TODO: Should we implement ToString for Secret and use that instead?
		blocks.push(secret.to_hex());

		if (total_read % (64*1024*1024)) == 0 {
			info!("Progress: {}MB of {}MB", (progress + total_read as u64) / (1024*1024), total_size / (1024*1024));
		}
	}

	if total_read as u64 != expected_size {
		// File was modified
		return (None, true);
	}

	(Some(blocks), false)
}
