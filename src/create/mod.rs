use keystore::{KeyStore, Secret};
use getopts::Options;
use std::fs;
use std::io::{Read, BufReader};
use block::BlockStore;
use std::path::{Path};
use std::os::unix::fs::MetadataExt;
use rustc_serialize::hex::{ToHex, FromHex};
use std::string::ToString;
use backend::{AcdBackend, FileBackend, Backend};
use archive::{Archive, File};
use rusqlite;

#[derive(Default)]
struct Config {
	/// If true, follow symlinks.
	/// If false, symlinks are saved as symlinks in the archive.
	pub dereference_symlinks: bool,
	/// If true, follow hardlinks.
	/// If false, hardlink are saved as hardlinks in the archive.
	pub dereference_hardlinks: bool,
}


pub fn execute(args: &[String]) {
	let mut opts = Options::new();
	opts.reqopt("", "keyfile", "set keyfile", "NAME");
	opts.reqopt("", "backend", "set backend", "BACKEND");
	opts.optopt("", "backend-path", "set backend path", "PATH");
	opts.optflag("", "dereference", "follow symlinks");
	opts.optflag("", "hard-dereference", "follow hardlinks");

	let matches = match opts.parse(args) {
		Ok(m) => m,
		Err(err) => panic!(err.to_string())
	};

	if matches.free.len() != 2 {
		println!("Usage: preserve create [OPTIONS] backup-name directory-to-backup");
		return;
	}

	let mut config = Config::default();
	let backup_name = matches.free[0].clone();
	let target_directory = Path::new(&matches.free[1].clone()).canonicalize().unwrap();

	config.dereference_symlinks = matches.opt_present("dereference");
	config.dereference_hardlinks = matches.opt_present("hard-dereference");

	let mut reader = BufReader::new(match matches.opt_str("keyfile") {
		Some(path) => fs::File::open(path).unwrap(),
		None => panic!("missing keyfile option"),
	});

	let keystore = KeyStore::load(&mut reader);
	let block_store = BlockStore::new(&keystore);
	let mut backend: Box<Backend> = {
		match &matches.opt_str("backend").unwrap()[..] {
			"acd" => Box::new(AcdBackend::new()),
			"file" => Box::new(FileBackend::new(matches.opt_str("backend-path").unwrap())),
			x => panic!("Unknown backend {}", x),
		}
	};

	let cache_conn = rusqlite::Connection::open("cache.sqlite").unwrap();

	cache_conn.execute("CREATE TABLE IF NOT EXISTS mtime_cache (
		path TEXT NOT NULL,
		mtime INTEGER NOT NULL,
		mtime_nsec INTEGER NOT NULL,
		size INTEGER NOT NULL,
		blocks TEXT NOT NULL
	)", &[]).unwrap();

	cache_conn.execute("CREATE INDEX IF NOT EXISTS idx_mtime_cache_path_mtime_size ON mtime_cache (path, mtime, mtime_nsec, size);", &[]).unwrap();
	cache_conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_mtime_cache_path ON mtime_cache (path);", &[]).unwrap();

	let (mut files, total_backup_size) = walk(&config, target_directory.clone(), 0);
	let mut progress = 0u64;

	read_files(&mut files, &target_directory, &block_store, &mut *backend, total_backup_size, &mut progress, &cache_conn);

	let archive = Archive {
		version: 0x00000001,
		name: backup_name,
		original_path: target_directory.to_str().unwrap().to_string(),
		files: files,
	};

	println!("Writing archive...");
	let (encrypted_archive_name, encrypted_archive) = archive.encrypt(&keystore);
	backend.store_archive(&encrypted_archive_name, &encrypted_archive);
	println!("Done");
}

fn walk<P: AsRef<Path>>(config: &Config, path: P, depth: usize) -> (Vec<File>, u64) {
	let mut files = Vec::new();
	let mut total_size = 0u64;

	let entries = match fs::read_dir(path.as_ref()) {
		Ok(x) => x,
		Err(err) => {
			println!("WARNING: Unable to read directory '{}'.  The following error was received: {}", path.as_ref().to_string_lossy(), err);
			return (files, total_size)
		}
	};

	for entry in entries {
		let entry = entry.unwrap();
		let file_type = match entry.file_type() {
			Ok(file_type) => file_type,
			Err(err) => {
				println!("WARNING: Unable to read '{}'.  The following error was received: {}", entry.path().to_string_lossy(), err);
				continue
			},
		};

		let (metadata, symlink_path) = if file_type.is_symlink() {
			if config.dereference_symlinks {
				(fs::metadata(entry.path()), None)
			} else {
				let symlink_path = match fs::read_link(entry.path()) {
					Ok(path) => path,
					Err(err) => {
						println!("WARNING: Unable to read '{}'.  The following error was received: {}", entry.path().to_string_lossy(), err);
						continue
					},
				};
				(entry.metadata(), Some(symlink_path.to_str().unwrap().to_string()))
			}
		} else {
			(entry.metadata(), None)
		};

		let metadata = match metadata {
			Ok(metadata) => metadata,
			Err(err) => {
				println!("WARNING: Unable to read '{}'.  The following error was received: {}", entry.path().to_string_lossy(), err);
				continue
			},
		};

		let (children, entry_size) = if let Some(_) = symlink_path {
			(Vec::new(), 0)
		} else if metadata.is_file() {
			(Vec::new(), metadata.len())
		} else if metadata.is_dir() {
			walk(config, entry.path(), depth + 1)
		} else {
			println!("WARNING: Skipping '{}' because it is not a symlink, directory, or regular file.", entry.path().to_string_lossy());
			continue;
		};

		total_size += entry_size;

		let file = File {
			path: entry.file_name().to_str().unwrap().to_string(),
			symlink: symlink_path,
			is_dir: metadata.is_dir(),
			mode: metadata.mode(),
			mtime: metadata.mtime(),
			mtime_nsec: metadata.mtime_nsec(),
			uid: metadata.uid(),
			gid: metadata.gid(),
			size: metadata.len(),
			children: children,
			blocks: Vec::new(),
		};

		files.push(file);
	}

	(files, total_size)
}


fn read_files<P: AsRef<Path>>(files: &mut Vec<File>, base_path: P, block_store: &BlockStore, backend: &mut Backend, total_size: u64, progress: &mut u64, cache_conn: &rusqlite::Connection) {
	// TODO: This whole method of removing files that we had trouble reading is awkward
	let mut dead_files = Vec::new();

	for file in &mut *files {
		let path = base_path.as_ref().join(&file.path);
		let is_symlink = match file.symlink {
			Some(_) => true,
			None => false,
		};

		if !file.is_dir && !is_symlink {
			println!("Reading file: {:?}", path.to_str());
			if !read_file(&path, file, block_store, backend, total_size, *progress, cache_conn) {
				dead_files.push(path.clone());
			}
			*progress += file.size;
			println!("Progress: {}MB of {}MB", *progress / (1024*1024), total_size / (1024*1024));
		}

		read_files(&mut file.children, path, block_store, backend, total_size, progress, cache_conn);
	}

	files.retain(|ref file| {
		let path = base_path.as_ref().join(&file.path);

		!dead_files.contains(&path)
	});
}


fn read_file<P: AsRef<Path>>(path: P, f: &mut File, block_store: &BlockStore, backend: &mut Backend, total_size: u64, progress: u64, cache_conn: &rusqlite::Connection) -> bool {
	let file = match fs::File::open(path.as_ref().clone()) {
		Ok(f) => f,
		Err(err) => {
			println!("WARNING: Unable to open file '{}' with the following error: {}.  It will not be included in the archive.", path.as_ref().to_string_lossy(), err);
			return false
		},
	};
	let reader = BufReader::new(&file);
	let reader_ref = reader.get_ref();
	let mut buffer = Vec::<u8>::new();
	let mut total_read = 0;
	let canonical = path.as_ref().canonicalize().unwrap();

	let result = cache_conn.query_row("SELECT blocks FROM mtime_cache WHERE path=? AND mtime=? AND mtime_nsec=? AND size=?", &[&canonical.to_str().unwrap().to_owned(), &f.mtime, &f.mtime_nsec, &(f.size as i64)], |row| {
		row.get(0)
	});

	match result {
		Ok(blocks) => {
			let mut need_reread = false;
			let blocks: String = blocks;
			if blocks.len() > 0 {
				for block in blocks.split('\n') {
					let secret = Secret::from_slice(&block.from_hex().unwrap()).unwrap();
					if !block_store.block_exists(&secret, backend) {
						need_reread = true;
						break;
					}
					f.blocks.push(block.to_owned());
				}
			}

			if !need_reread {
				println!("Found in mtime cache.");
				return true;
			}
		},
		Err(rusqlite::Error::QueryReturnedNoRows) => (),
		Err(err) => panic!("Sqlite error: {}", err),
	};

	loop {
		buffer.clear();
		reader_ref.take(1024*1024).read_to_end(&mut buffer).unwrap();

		if buffer.len() == 0 {
			break;
		}

		total_read += buffer.len();

		let Secret(secret) = block_store.new_block_from_plaintext(&buffer, backend);
		f.blocks.push(secret.to_hex());

		if (total_read % (64*1024*1024)) == 0 {
			println!("Progress: {}MB of {}MB", (progress + total_read as u64) / (1024*1024), total_size / (1024*1024));
		}
	}

	if total_read as u64 != f.size {
		println!("Size mismatch: {} != {}", total_read, f.size);
	}

	if total_read as u64 == f.size {
		let blocks = f.blocks.join("\n");
		cache_conn.execute("INSERT OR REPLACE INTO mtime_cache (path, mtime, mtime_nsec, size, blocks) VALUES (?,?,?,?,?)", &[&canonical.to_str().unwrap().to_owned(), &f.mtime, &f.mtime_nsec, &(f.size as i64), &blocks]).unwrap();
	}

	true
}
