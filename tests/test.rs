extern crate tempdir;

use std::process::Command;
use std::fs::File;
use std::path::Path;
use std::io::Write;
use tempdir::TempDir;

fn create_backup<P: AsRef<Path>>(temp_path: P, bin_path: P, backend_path: P, backup_name: &str, target_dir: P) {
	// Backup
	Command::new(bin_path.as_ref())
		.current_dir(temp_path.as_ref())
		.arg("create")
		.arg("--keyfile").arg("keyfile")
		.arg("--backend").arg("file")
		.arg("--backend-path").arg(backend_path.as_ref())
		.arg(backup_name)
		.arg(target_dir.as_ref())
		.output().unwrap();
}

fn restore_and_check<P: AsRef<Path>>(temp_path: P, bin_path: P, backend_path: P, original_path: P, backup_name: &str) -> Option<String> {
	let restore_dir = TempDir::new("preserve-test").unwrap();

	// Restore
	Command::new(bin_path.as_ref())
		.current_dir(temp_path.as_ref())
		.arg("restore")
		.arg("--keyfile").arg("keyfile")
		.arg("--backend").arg("file")
		.arg("--backend-path").arg(backend_path.as_ref())
		.arg(backup_name)
		.arg(restore_dir.path())
		.output().unwrap();

	// Compare using rsync, which will compare mtime, permissions, contents, etc.
	let output = Command::new("rsync")
		.arg("-avnc")     // Archive mode, verbose, dry-run, checksum
		.arg("--delete")  // Check for missing files
		.arg(original_path.as_ref().to_str().unwrap().to_string() + "/")
		.arg(restore_dir.path().to_str().unwrap().to_string() + "/")
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
		None
	} else {
		Some(output.to_string())
	}
}

#[test]
fn integration_test_1() {
	let temp_dir = TempDir::new("preserve-test").unwrap();
	let backend_dir = TempDir::new("preserve-test").unwrap();
	let bin_path = Path::new("target/debug/preserve").canonicalize().unwrap();

	// Generate keyfile
	Command::new(&bin_path)
		.current_dir(temp_dir.path())
		.arg("keygen")
		.arg("--keyfile").arg(temp_dir.path().join("keyfile"))
		.output().unwrap();

	// Test case
	let original1_dir = TempDir::new("preserve-test").unwrap();
	Command::new("tar")
		.arg("xf")
		.arg("tests/testcase.tar")
		.arg("-C")
		.arg(original1_dir.path())
		.output().unwrap();

	create_backup(temp_dir.path(), &bin_path, backend_dir.path(), "test1", original1_dir.path());
	match restore_and_check(temp_dir.path(), &bin_path, backend_dir.path(), original1_dir.path(), "test1") {
		Some(err) => panic!("Restored backup did not match original1.  rsync output:\n{}", err),
		None => ()
	};

	// Create file
	{
		let mut file = File::create(original1_dir.path().join("test.txt")).unwrap();
		file.write_all(b"This is a new file").unwrap();
	}

	create_backup(temp_dir.path(), &bin_path, backend_dir.path(), "test2", original1_dir.path());
	match restore_and_check(temp_dir.path(), &bin_path, backend_dir.path(), original1_dir.path(), "test2") {
		Some(err) => panic!("Restored backup did not match original1 after create file.  rsync output:\n{}", err),
		None => ()
	};

	// Modify file
	{
		let mut file = File::create(original1_dir.path().join("test.txt")).unwrap();
		file.write_all(b"This is a different file").unwrap();
	}

	create_backup(temp_dir.path(), &bin_path, backend_dir.path(), "test3", original1_dir.path());
	match restore_and_check(temp_dir.path(), &bin_path, backend_dir.path(), original1_dir.path(), "test3") {
		Some(err) => panic!("Restored backup did not match original1 after modify file.  rsync output:\n{}", err),
		None => ()
	};

	// Check old backup
	let original2_dir = TempDir::new("preserve-test").unwrap();
	Command::new("tar")
		.arg("xf")
		.arg("tests/testcase.tar")
		.arg("-C")
		.arg(original2_dir.path())
		.output().unwrap();

	match restore_and_check(temp_dir.path(), &bin_path, backend_dir.path(), original2_dir.path(), "test1") {
		Some(err) => panic!("Restore old backup did not match original2.  rsync output:\n{}", err),
		None => ()
	};

	// False check
	match restore_and_check(temp_dir.path(), &bin_path, backend_dir.path(), original1_dir.path(), "test1") {
		None => panic!("Sanity check failed.  Restoring test1 should not match original1_dir."),
		Some(_) => (),
	};
}
