#!/usr/bin/env python3
# TODO: Use a Docker library instead
import subprocess
import os
import tempfile
import shutil


def main():
	os.makedirs("logs", exist_ok=True)

	# Create temporary folders to hold the backup data and then restored result
	backup_dir = tempfile.mkdtemp(prefix="preserve-docker-test-backup-")

	# NOTE: On macOS (as of 2019.01.18) mktemp et al return a path starting with '/var'.
	# Docker for macOS, by default, won't mount '/var' paths.
	# But '/var' is actually a symlink to '/private' which Docker for macOS will mount.
	# So we use realpath to resolve the symlink.
	backup_dir = os.path.realpath(backup_dir)

	# Copy preserve source code for Docker
	shutil.rmtree('src/preserve-src', ignore_errors=True)
	shutil.copytree('../../src', 'src/preserve-src/src')
	shutil.copy('../../Cargo.toml', 'src/preserve-src/')
	shutil.copy('../../Cargo.lock', 'src/preserve-src/')

	# Build the test image
	print("Building Docker image...")
	run_command(['docker', 'build', '-t', 'preserve-test', '-f', 'src/Dockerfile', 'src'], logpath='logs/docker.build.log')

	# Backup
	print("Running backup container...")
	run_command(['docker', 'run', '-v', "{}:/backup".format(backup_dir), '--name', 'preserve-test-backup', 'preserve-test', 'bash', 'create-backup.sh'], logpath='logs/docker.run.backup.log')
	run_command(['docker', 'export', 'preserve-test-backup'], logpath='exported-backup-image.tar')
	run_command(['docker', 'rm', 'preserve-test-backup'])

	# Restore and Compare
	# Comparison results are printed to stderr
	print("Running restore container...")
	run_command(['docker', 'run', '-v', "{}:/backup".format(backup_dir), '-v', '{}:/exported-backup-image.tar'.format(os.path.join(os.getcwd(), 'exported-backup-image.tar')), '--rm', 'preserve-test', 'bash', 'restore-backup.sh'], logpath='logs/docker.run.restore.log')

	# Done
	print()
	print("NOTE: ")
	print("Left behind the following folders/files, in case they are needed for inspection:")
	print(backup_dir)
	print("exported-backup-image.tar")
	print("logs/*")


def run_command(args, logpath=None, stderr=None, check=True):
	result = subprocess.run(args, stdout=subprocess.PIPE, check=check, stderr=stderr)
	if logpath is not None:
		with open(logpath, 'wb') as f:
			f.write(result.stdout)
	
	return result


main()