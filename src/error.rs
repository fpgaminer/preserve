use std::error::Error as StdError;
use std::io::Error as IoError;
use rustc_serialize::json::DecoderError as JsonDecoderError;
use rusqlite::Error as SqliteError;
use std::fmt;
use self::Error::*;

pub type Result<T> = ::std::result::Result<T, Error>;


#[derive(Debug)]
pub enum Error {
	/// I/O error
	Io(IoError),
	/// Error from JSON decoder
	JsonDecoder(JsonDecoderError),
	/// Bad Backend Path
	BadBackendPath(String),
	ArchiveNameTooLong,
	CorruptArchiveName,
	CorruptArchiveTruncated,
	CorruptArchiveBadHmac,
	CorruptArchiveFailedDecompression,
	CorruptArchiveNotUtf8,
	CorruptArchiveBadJson,
	CorruptArchiveBadBlockSecret,
	CorruptBlock,
	ArchiveNameConflict,
	BlockNotFound,
	ArchiveNotFound,
	InvalidArchiveName,
	BackendOnDifferentDevices,
	Sqlite(SqliteError),
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.write_str(self.description())
	}
}

impl StdError for Error {
	fn description(&self) -> &str {
		match *self {
			Io(ref e) => e.description(),
			JsonDecoder(_) => "Invalid JSON",
			BadBackendPath(ref e) => e,
			ArchiveNameTooLong => "The archive name must be <= 127 bytes (UTF-8)",
			CorruptArchiveName => "The encrypted archive name is corrupted",
			CorruptArchiveTruncated => "The encrypted archive is corrupted: Truncated",
			CorruptArchiveBadHmac => "The encrypted archive is corrupt: Bad Hmac",
			CorruptArchiveFailedDecompression => "The encrypted archive is corrupt: could not be decompressed",
			CorruptArchiveNotUtf8 => "The encrypted archive is corrupt: data is not UTF-8",
			CorruptArchiveBadJson => "The encrypted archive is corrupt: the internal JSON data is invalid",
			CorruptBlock => "The encrypted block is corrupted",
			BlockNotFound => "The specified block was not found",
			ArchiveNotFound => "The specified archive was not found",
			InvalidArchiveName => "An invalid archive name was encountered.  Possibly a stray file.",
			ArchiveNameConflict => "An archive with that name already exists",
			BackendOnDifferentDevices => "All folders in the backend must be on the same drive",
			Sqlite(ref e) => e.description(),
			CorruptArchiveBadBlockSecret => "The archive is corrupted.  One of the block secrets could not be parsed",
		}
	}

	fn cause(&self) -> Option<&StdError> {
		match *self {
			Io(ref error) => Some(error),
			JsonDecoder(ref error) => Some(error),
			BadBackendPath(_) => None,
			ArchiveNameTooLong => None,
			CorruptArchiveName => None,
			CorruptArchiveTruncated => None,
			CorruptArchiveBadHmac => None,
			CorruptArchiveFailedDecompression => None,
			CorruptArchiveNotUtf8 => None,
			CorruptArchiveBadJson => None,
			CorruptBlock => None,
			ArchiveNameConflict => None,
			BlockNotFound => None,
			InvalidArchiveName => None,
			ArchiveNotFound => None,
			BackendOnDifferentDevices => None,
			Sqlite(ref error) => Some(error),
			CorruptArchiveBadBlockSecret => None,
		}
	}
}

impl From<IoError> for Error {
	fn from(err: IoError) -> Error {
		Io(err)
	}
}

impl From<JsonDecoderError> for Error {
	fn from(err: JsonDecoderError) -> Error {
		JsonDecoder(err)
	}
}

impl From<SqliteError> for Error {
	fn from(err: SqliteError) -> Error {
		Sqlite(err)
	}
}
