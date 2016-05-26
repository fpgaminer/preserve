use keystore::{KeyStore, Secret, BlockId};
use getopts::Options;
use std::fs;
use std::io::{self, BufReader, BufWriter, Write, SeekFrom, Seek, Read};
use block::BlockStore;
use std::path::{Path, PathBuf};
use std::os::unix::fs::{MetadataExt, DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::collections::HashMap;
use rustc_serialize::hex::FromHex;
use backend::{FileBackend, AcdBackend, Backend};
use archive::{Archive, File};
use tempdir::TempDir;


struct DownloadCache {
	refcount: u64,
	downloaded: bool,
	secret: Secret,
	id: BlockId,
}


pub fn execute(args: &[String]) {
	let mut opts = Options::new();
	opts.reqopt("", "keyfile", "set keyfile", "NAME");
	opts.optflag("", "debug-decrypt", "just fetch and decrypt the archive; no decompression, no parsing, no extraction");
	opts.reqopt("", "backend", "set backend", "BACKEND");
	opts.optopt("", "backend-path", "set backend path", "PATH");
	opts.optflag("", "hard-dereference", "dereference hardlinks");

	let matches = match opts.parse(args) {
		Ok(m) => m,
		Err(err) => panic!(err.to_string())
	};

	let debug_decrypt = matches.opt_present("debug-decrypt");

	if (debug_decrypt && matches.free.len() != 1) || (!debug_decrypt && matches.free.len() != 2) {
		println!("Usage: preserve restore backup-name directory-to-extract-to [OPTIONS]");
		return;
	}

	let backup_name = matches.free[0].clone();
	let target_directory = if matches.free.len() > 1 {
		Path::new(&matches.free[1].clone()).canonicalize().unwrap()
	} else {
		PathBuf::new()
	};

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

	let mut config = Config::default();

	config.dereference_hardlinks = matches.opt_present("hard-dereference");

	let encrypted_archive_name = keystore.encrypt_archive_name(&backup_name);
	let encrypted_archive = backend.fetch_archive(&encrypted_archive_name);

	if debug_decrypt {
		let decrypted = keystore.decrypt_archive(&encrypted_archive_name, &encrypted_archive);
		io::stdout().write(&decrypted).unwrap();
		return;
	}

	let archive = Archive::decrypt(&encrypted_archive_name, &encrypted_archive, &keystore);

	if archive.version != 0x00000001 {
		panic!("Unsupported archive version");
	}

	let download_cache_dir = TempDir::new("preserve-").unwrap();
	let mut download_cache = HashMap::new();

	build_block_refcounts(&archive.files, &keystore, &mut download_cache);

	extract_files(&config, &archive.files, target_directory.to_str().unwrap(), &block_store, download_cache_dir.path(), &mut download_cache, &mut *backend, );
}


#[derive(Default)]
struct Config {
	/// If true, hardlinks will be removed by cloning the file at all places it is referenced.
	/// If false, hardlinks are preserved.
	pub dereference_hardlinks: bool,
}


fn build_block_refcounts(files: &[File], keystore: &KeyStore, download_cache: &mut HashMap<String, DownloadCache>) {
	for file in files {
		build_block_refcounts_helper(file, keystore, download_cache);
	}
}


fn build_block_refcounts_helper(file: &File, keystore: &KeyStore, download_cache: &mut HashMap<String, DownloadCache>) {
	for secret_str in &file.blocks {
		let secret = Secret::from_slice(&secret_str.from_hex().unwrap()).unwrap();
		let block_id = keystore.block_id_from_block_secret(&secret);

		download_cache.entry(secret_str.clone()).or_insert(DownloadCache{
			refcount: 0,
			downloaded: false,
			id: block_id,
			secret: secret,
		});
		download_cache.get_mut(secret_str).unwrap().refcount += 1;
	}
}


fn extract_files<P: AsRef<Path>>(config: &Config, files: &[File], base_path: P, block_store: &BlockStore, cache_dir: &Path, download_cache: &mut HashMap<String, DownloadCache>, backend: &mut Backend) {
	let mut hardlink_map: HashMap<u64, PathBuf> = HashMap::new();
	// List of all directories and the mtimes they need set.
	// We set these after extracting all files, since extracting the files changes the mtime of
	// directories.
	let mut directory_times = Vec::new();

	for file in files {
		let filepath = base_path.as_ref().join(&file.path);

		if let Some(ref symlink_path) = file.symlink {
			use std::os::unix;
			println!("Creating symlink: {} {}", symlink_path, filepath.display());
			unix::fs::symlink(symlink_path, &filepath).unwrap();
		} else if file.is_dir {
			println!("Creating directory: {}", filepath.display());
			// Create and then set permissions.  This is done in two steps because
			// mkdir is affected by the current process's umask, whereas chmod (set_permissions) is not.
			fs::create_dir(&filepath).unwrap();
			fs::set_permissions(&filepath, fs::Permissions::from_mode(file.mode)).unwrap();
			directory_times.push((filepath.clone(), file.mtime, file.mtime_nsec));
		} else {
			let hardlinked = if let Some(hardlink_id) = file.hardlink_id {
				if config.dereference_hardlinks {
					false
				} else {
					match hardlink_map.get(&hardlink_id) {
						Some(existing_path) => {
							println!("Hardlinking '{}' to '{}'", existing_path.display(), filepath.display());
							fs::hard_link(existing_path, &filepath).unwrap();
							true
						},
						None => false,
					}
				}
			} else {
				false
			};

			if !hardlinked {
				println!("Writing file: {}", filepath.display());
				// We set permissions after creating the file because `open` uses umask.
				extract_file(&filepath, file, block_store, cache_dir, download_cache, backend);
				fs::set_permissions(&filepath, fs::Permissions::from_mode(file.mode)).unwrap();

				if !config.dereference_hardlinks {
					if let Some(hardlink_id) = file.hardlink_id {
						hardlink_map.insert(hardlink_id, filepath.clone());
					}
				}
			}
		}

		set_file_time(&filepath, file.mtime, file.mtime_nsec);
	}

	// Set mtime for directories.
	// We go in reverse, so we hit child directories before their parents
	directory_times.reverse();

	for (ref dirpath, ref mtime, ref mtime_nsec) in directory_times {
		set_file_time(dirpath, *mtime, *mtime_nsec);
	}
}


fn extract_file<P: AsRef<Path>>(path: P, f: &File, block_store: &BlockStore, cache_dir: &Path, download_cache: &mut HashMap<String, DownloadCache>, backend: &mut Backend) {
	// TODO: Don't overwrite files?
	let mut file = fs::OpenOptions::new().write(true).create(true).open(path.as_ref()).unwrap();

	/* TODO: This doesn't seem like a bulletproof way to do this */
	/* Check if file exists */
	if file.seek(SeekFrom::End(0)).unwrap() != 0 {
		println!("File {} Already Exists", path.as_ref().to_str().unwrap());
		return;
	}

	let mut writer = BufWriter::new(&file);
	let mut total_written = 0;

	for secret in &f.blocks {
		let plaintext = cache_fetch(secret, block_store, cache_dir, download_cache, backend);

		writer.write_all(&plaintext).unwrap();
		total_written += plaintext.len();
	}

	if total_written as u64 != f.size {
		println!("Size mismatch: {} != {}", total_written, f.size);
	}
}


fn cache_fetch(secret_str: &str, block_store: &BlockStore, cache_dir: &Path, download_cache: &mut HashMap<String, DownloadCache>, backend: &mut Backend) -> Vec<u8> {
	let cache = download_cache.get_mut(secret_str).unwrap();
	let path = cache_dir.join(cache.id.to_string());

	if cache.downloaded {
		let plaintext = {
			let mut file = fs::File::open(path.clone()).unwrap();
			let mut plaintext = vec![0u8; 0];
			file.read_to_end(&mut plaintext).unwrap();
			plaintext
		};

		cache.refcount -= 1;

		if cache.refcount == 0 {
			fs::remove_file(path).unwrap();
		}

		return plaintext;
	}

	let plaintext = block_store.fetch_block(&cache.secret, backend);

	cache.refcount -=1;
	cache.downloaded = true;

	if cache.refcount > 0 {
		let mut file = fs::File::create(path).unwrap();
		file.write_all(&plaintext).unwrap();
	}

	plaintext
}


fn set_file_time(path: &Path, mtime: i64, mtime_nsec: i64) {
	use std::ffi::CString;
	use std::os::unix::prelude::*;
	use libc::{time_t, timespec, utimensat, c_long, AT_FDCWD, AT_SYMLINK_NOFOLLOW};
	use std::io;

	let times = [timespec {
		tv_sec: mtime as time_t,
		tv_nsec: mtime_nsec as c_long,
	},
	timespec {
		tv_sec: mtime as time_t,
		tv_nsec: mtime_nsec as c_long,
	}];
	let p = CString::new(path.as_os_str().as_bytes()).unwrap();

	unsafe {
		if utimensat(AT_FDCWD, p.as_ptr() as *const _, times.as_ptr(), AT_SYMLINK_NOFOLLOW) == 0 {
			Ok(())
		} else {
			Err(io::Error::last_os_error())
		}
	}.unwrap();
}
