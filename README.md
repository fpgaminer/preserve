# Preserve [![Build Status](https://travis-ci.org/cholcombe973/preserve.svg?branch=master)](https://travis-ci.org/cholcombe973/preserve) #
Preserve is an encrypted backup system written in Rust.  All backup data is encrypted, so backups can be stored on untrusted devices/services without exposing any of your data.  Backups are simple, operating very similar to creating an archive like Zip or Tar.  Deduplication makes this space efficient.

## Usage

1. Generate a keyfile without vault.

   ```
   preserve keygen --keyfile keyfile
   ```

    Make sure to store this keyfile in a safe place.  Anyone who has access to this keyfile can read your backups and/or corrupt them. If you build
    preserve with the `vault` feature you can store the key in hashicorp-vault. Preserve will then pull down the key as needed so it doesn't need to
    be stored locally.

    The vault key storage uses the `.config/vault.json` file to configure it. Fields for this file are:
  ```
  {
   "host": "http://localhost:8200",
   "token": "<token>",
  }
  ```

    Generating a keyfile with vault:
    ```
    preserve keygen
    ```
2. Configure your backend.

  Ceph is supported as a backend. Use `--backend ceph`. The ceph backend uses the
`.config/ceph.json` file to configure it. Fields for this file are:
```
{
 "config_file": "/etc/ceph/ceph.conf",
 "user_id": "admin",
 "data_pool": "data",
 "metadata_pool": "metadata"
}
```
The Ceph backend requires librados to be installed on your system. For Ubuntu that
package is called `librados-dev`

  Gluster is supported as a backend. Use `--backend gluster`. The gluster backend uses the
`.config/gluster.json` file to configure it.
```
{
    "server": "192.168.1.2",
    "port": 24007,
    "volume_name": "test"
}
```
The Gluster backend requires libgfapi to be installed on your system.  For Ubuntu
that package is called `glusterfs-common`
Other backends include file and ACD ( Amazon Cloud Drive).

  Amazon Cloud Drive is supported as a backend using `--backend acd`.  Setup instructions for ACD are forthcoming.


3. Create a backup

   ```
   preserve create --keyfile keyfile --backend file --backend-path /path/to/my/backups/ my-backup-`date +%Y-%m-%d_%H-%M-%S` /home/me/
   ```

   This will create a backup of everything inside `/home/me/`, the backup will be called `my-backup-2016-02-25_11-56-51`, the backup will be stored in the filesystem at `/path/to/my/backups`.  To take advantage of deduplication you should store all your backups in the same place.  If you backup multiple machines, you could use an external drive or NAS.  If you use the same keyfile for all machines then Preserve will dedup across all machines.

4. List backups

   ```
   preserve list --keyfile keyfile --backend file --backend-path /path/to/my/backups/
   ```

5. Restore a backup

   ```
   preserve restore --keyfile keyfile --backend file --backend-path /path/to/my/backups/ name-of-backup-to-restore /path/to/restore/it/to/
   ```

   This will restore the backup named `name-of-backup-to-restore`, extracting its contents to `/path/to/restore/it/to/`

## Build
The Ceph and Gluster backends are hidden behind config feature flags.  To enable
them use cargo build with the `--features` flag and specify either one or both
of the backends.
`cargo build --features "ceph gluster"`. Make sure you have `librados-dev` and
`glusterfs-common` installed or these backends will fail to link properly.
The vault key storage requires the `--features "vault"` flag to be built.

## Test
```
cargo test
```

## Details
It's easiest to understand Preserve by going through how it creates a backup.  When you tell Preserve to create a backup, it walks the specified path looking for all files and folders.  It collects information about all those files and folders (name, permissions, mtime, size) in a tree data structure.  Then it goes through all the files and reads their contents.  It reads file contents 1MB at a time.  For each 1MB chunk, it encrypts the chunk using convergent encryption.  Convergent encryption is determinsitic, so given the same 1MB chunk it will output the same 1MB encrypted block (plus id and mac).  Each block also has a small (32 bytes) unique identifier associated with it.  So after Preserve has finished reading all the chunks of a file, it stores the contents in the tree data structure as a list of these unique identifiers, and stores the actual blocks on the backend.  When it encounters the same block twice, it has to store the metadata twice, but the actual encrypted data only gets stored once on the backend.  This is how Preserve achieves its deduplication.  If you create one backup, and then create another of the same exact data, Preserve won't have to store any new blocks on the backend.  It would only need to store a new set of metadata.

When all files have been traversed, the tree data structure is serialized to JSON, compressed with XZ, encrypted using a public key, and then stored at the backend.

Various caches are used to speed this process up.  If a file hasn't changed since Preserve last backed it up, then it will pull its metadata and list of content identifiers from cache.  So it won't actually have to re-read the file.
