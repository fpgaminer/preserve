extern crate tempdir;
extern crate rand;
extern crate libc;

use std::process::Command;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::io::{Write, BufWriter};
use tempdir::TempDir;
use rand::{Rng, ChaChaRng};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, MetadataExt};
use std::cmp;


#[test]
fn integration_test_1() {
	let working_dir = TempDir::new("preserve-test").unwrap();
	let backend_dir = TempDir::new("preserve-test").unwrap();

	let test_config = TestConfig {
		bin: Path::new("target/debug/preserve").canonicalize().unwrap(),
		working_dir: working_dir.path().to_path_buf(),
		backend_dir: backend_dir.path().to_path_buf(),
	};

	// Generate keyfile
	test_config.init();

	// Test case
	let original_dir = generate_test_case();

	// First test
	{
		test_config.create("test1", original_dir.path());
		let restore_dir = test_config.restore("test1");
		match compare_dirs(original_dir.path(), restore_dir.path()) {
			Ok(_) => (),
			Err(err) => handle_failed_restore(original_dir.path(), restore_dir.path(), "Restored directory did not match original directory", &err),
		};
	}

	// Add a file
	{
		let mut file = File::create(original_dir.path().join("test.txt")).unwrap();
		file.write_all(b"This is a new file").unwrap();
	}

	// Test again
	{
		test_config.create("test2", original_dir.path());
		let restore_dir = test_config.restore("test2");
		match compare_dirs(original_dir.path(), restore_dir.path()) {
			Ok(_) => (),
			Err(err) => handle_failed_restore(original_dir.path(), restore_dir.path(), "Restored directory did not match original directory with added file", &err),
		};
	}

	// Modify a file
	{
		let mut file = File::create(original_dir.path().join("test.txt")).unwrap();
		file.write_all(b"This is a different file").unwrap();
	}

	// Test again
	{
		test_config.create("test3", original_dir.path());
		let restore_dir = test_config.restore("test3");
		match compare_dirs(original_dir.path(), restore_dir.path()) {
			Ok(_) => (),
			Err(err) => handle_failed_restore(original_dir.path(), restore_dir.path(), "Restored directory did not match original directory with modified file", &err),
		};
	}

	// Check old backup
	let original_dir = generate_test_case();

	{
		let restore_dir = test_config.restore("test1");
		match compare_dirs(original_dir.path(), restore_dir.path()) {
			Ok(_) => (),
			Err(err) => handle_failed_restore(original_dir.path(), restore_dir.path(), "Restored directory did not match old original directory", &err),
		};
	}

	// Inverse test to make sure things are working as expected
	{
		let restore_dir = test_config.restore("test2");
		match compare_dirs(original_dir.path(), restore_dir.path()) {
			Ok(_) => handle_failed_restore(original_dir.path(), restore_dir.path(), "Restored test2 should not match old original directory", ""),
			Err(_) => (),
		};
	}
}


// Information about the current test, such as the temporary directories where we're storing
// the keyfile, backend path, etc.
struct TestConfig {
	pub bin: PathBuf,
	pub working_dir: PathBuf,
	pub backend_dir: PathBuf,
}

impl TestConfig {
	pub fn init(&self) {
		Command::new(&self.bin)
			.current_dir(&self.working_dir)
			.arg("keygen")
			.arg("--keyfile").arg("keyfile")
			.output().unwrap();
	}

	pub fn create<P: AsRef<Path>>(&self, backup_name: &str, path: P) {
		Command::new(&self.bin)
			.current_dir(&self.working_dir)
			.arg("create")
			.arg("--keyfile").arg("keyfile")
			.arg("--backend").arg("file")
			.arg("--backend-path").arg(&self.backend_dir)
			.arg(backup_name)
			.arg(path.as_ref())
			.output().unwrap();
	}

	pub fn restore(&self, backup_name: &str) -> TempDir {
		let restore_dir = TempDir::new("preserve-test").unwrap();

		Command::new(&self.bin)
			.current_dir(&self.working_dir)
			.arg("restore")
			.arg("--keyfile").arg("keyfile")
			.arg("--backend").arg("file")
			.arg("--backend-path").arg(&self.backend_dir)
			.arg(backup_name)
			.arg(restore_dir.path())
			.output().unwrap();

		restore_dir
	}
}


// Generate a file at the given path with random binary data of the given length.
// The file's permissions will be random, but OR'd with mode_or so you can force certain permissions.
// The file mtime will be a random variation on base_time.
fn generate_random_file<P: AsRef<Path>>(path: P, rng: &mut Box<Rng>, mode_or: u32, len: usize, base_time: i64) {
	let mode = (rng.next_u32() & 511) | mode_or;
	let time = base_time + rng.gen_range(-256000, 256000);
	let time_nsec = rng.gen_range(0, 1000000000);
	{
		let file = fs::OpenOptions::new().write(true).create(true).mode(mode).open(path.as_ref()).unwrap();
		let mut writer = BufWriter::new(file);
		let mut written = 0;
		let mut buffer = [0u8; 4096];

		while written < len {
			let chunk_size = cmp::min(buffer.len(), len - written);

			rng.fill_bytes(&mut buffer);
			writer.write_all(&buffer[..chunk_size]).unwrap();
			written += chunk_size;
		}
	}

	set_file_time(path, time, time_nsec);
}

// Fill destination folder with our test case, which we will backup, restore, modify, etc for the various tests.
fn generate_test_case() -> TempDir {
	let path = TempDir::new("preserve-test").unwrap();
	let base_time = 1456713592;

	// Deterministic seed
	let mut rng: Box<Rng> = Box::new(ChaChaRng::new_unseeded());

	let len = rng.gen_range(1, 4*1024*1024);
	generate_random_file(path.path().join("foo.bin"), &mut rng, 0o400, len, base_time);
	let len = rng.gen_range(1, 4*1024*1024);
	generate_random_file(path.path().join("foo2.bin"), &mut rng, 0o400, len, base_time);
	let len = rng.gen_range(1, 1*1024*1024);
	generate_random_file(path.path().join("testfile.txt"), &mut rng, 0o400, len, base_time);
	let len = rng.gen_range(1, 1*1024*1024);
	generate_random_file(path.path().join("testfile2.txt"), &mut rng, 0o400, len, base_time);
	generate_random_file(path.path().join("EMPTY"), &mut rng, 0o400, 0, base_time);

	fs::DirBuilder::new().mode(rng.gen_range(0, 512) | 0o700).create(path.path().join("testfolder")).unwrap();
	let len = rng.gen_range(1, 4*1024*1024);
	generate_random_file(path.path().join("testfolder").join("foo.bin"), &mut rng, 0o400, len, base_time);
	let len = rng.gen_range(1, 1*1024*1024);
	generate_random_file(path.path().join("testfolder").join("preserve_me"), &mut rng, 0o400, len, base_time);

	let time = rng.gen_range(base_time-256000, base_time+256000);
	set_file_time(path.path().join("testfolder"), time, rng.gen_range(0, 1000000000));

	path
}

// Compares the given directories using rsync.
// The returned error String is the output of rsync when they don't match.
fn compare_dirs<P: AsRef<Path>, Q: AsRef<Path>>(path1: P, path2: Q) -> Result<(), String> {
	// rsync should compare mtime, permissions, contents, etc.
	let output = Command::new("rsync")
		.arg("-avnc")     // Archive mode, verbose, dry-run, checksum
		.arg("--delete")  // Check for missing files
		.arg(path1.as_ref().to_str().unwrap().to_string() + "/")
		.arg(path2.as_ref().to_str().unwrap().to_string() + "/")
		.output().unwrap();

	let output = String::from_utf8_lossy(&output.stdout);
	let mut output_lines = output.lines();

	let mut same = true;

	same &= output_lines.next().unwrap_or("x") == "sending incremental file list";
	same &= match output_lines.next().unwrap_or("x") {
		"./" => output_lines.next().unwrap_or("x") == "",
		"" => true,
		_ => false,
	};
	same &= output_lines.next().unwrap_or("x").starts_with("sent ");
	same &= output_lines.next().unwrap_or("x").starts_with("total ");

	if same {
		Ok(())
	} else {
		Err(output.to_string())
	}
}

// We use temporary directories for everything, so in the case of failure save the directories
// for inspection, and then panic with the error message.
fn handle_failed_restore<P: AsRef<Path>, Q: AsRef<Path>>(original_dir: P, restore_dir: Q, reason: &str, err: &str) {
	let mut rng = rand::thread_rng();
	let random_str: String = rng.gen_ascii_chars().take(10).collect();

	fs::rename(original_dir, "/tmp/preserve-test-failed-original-".to_string() + &random_str).unwrap();
	fs::rename(restore_dir, "/tmp/preserve-test-failed-restore-".to_string() + &random_str).unwrap();
	panic!("{}\nOriginal and Restore directories have been saved for inspection: /tmp/preserve-test-failed-*-{}\nrsync output:\n{}", reason, random_str, err)
}

fn set_file_time<P: AsRef<Path>>(path: P, mtime: i64, mtime_nsec: i64) {
	use std::ffi::CString;
	use std::os::unix::prelude::*;
	use libc::{timeval, time_t, suseconds_t, utimes};
	use std::io;

	// TODO: Using utimensat would allow setting time with nanosecond accuracy (instead of microsecond accuracy).

	let times = [timeval {
		tv_sec: mtime as time_t,
		tv_usec: (mtime_nsec / 1000) as suseconds_t,
	},
	timeval {
		tv_sec: mtime as time_t,
		tv_usec: (mtime_nsec / 1000) as suseconds_t,
	}];
	let p = CString::new(path.as_ref().as_os_str().as_bytes()).unwrap();

	unsafe {
		if utimes(p.as_ptr() as *const _, times.as_ptr()) == 0 {
			Ok(())
		} else {
			Err(io::Error::last_os_error())
		}
	}.unwrap();
}

/*fn dump_metadata<P: AsRef<Path>>(path: P) {
	let metadata = path.as_ref().metadata().unwrap();
	println!("{:?}", path.as_ref());
   println!("dev: {:?}", metadata.dev());
            println!("ino: {:?}", metadata.ino());
            println!("mode: {:?}", metadata.mode());
            println!("nlink: {:?}", metadata.nlink());
            println!("uid: {:?}", metadata.uid());
            println!("gid: {:?}", metadata.gid());
            println!("rdev: {:?}", metadata.rdev());
            println!("size: {:?}", metadata.size());
            println!("atime: {:?}", metadata.atime());
            println!("atime_nsec: {:?}", metadata.atime_nsec());
            println!("mtime: {:?}", metadata.mtime());
            println!("mtime_nsec: {:?}", metadata.mtime_nsec());
            println!("ctime: {:?}", metadata.ctime());
            println!("ctime_nsec: {:?}", metadata.ctime_nsec());
            println!("blksize: {:?}", metadata.blksize());
            println!("blocks: {:?}", metadata.blocks());
}*/
