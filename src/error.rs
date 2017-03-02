use acd::Error as AcdError;
use rusqlite::Error as SqliteError;
use rustc_serialize::json::DecoderError as JsonDecoderError;
use std::error::Error as StdError;
use std::fmt;
use std::io::Error as IoError;
use self::Error::*;

pub type Result<T> = ::std::result::Result<T, Error>;


#[derive(Debug)]
pub enum Error {
    ArchiveNameConflict,
    ArchiveNameTooLong,
    ArchiveNotFound,
    Acd(AcdError),
    BackendOnDifferentDevices,
    /// Bad Backend Path
    BadBackendPath(String),
    BlockNotFound,
    CorruptArchiveName,
    CorruptArchiveTruncated,
    CorruptArchiveBadHmac,
    CorruptArchiveFailedDecompression,
    CorruptArchiveNotUtf8,
    CorruptArchiveBadJson,
    CorruptArchiveBadBlockSecret,
    CorruptBlock,
    FromUtf8Error(::std::string::FromUtf8Error),
    /// I/O error
    Io(IoError),
    /// Error from JSON decoder
    JsonDecoder(JsonDecoderError),
    InvalidArchiveName,
    #[cfg(feature = "gluster")]
    GlusterError(::gfapi_sys::gluster::GlusterError),
    #[cfg(feature = "ceph")]
    RadosError(::ceph_rust::ceph::RadosError),
    Sqlite(SqliteError),
    VaultError(::vault::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            VaultError(ref e) => write!(f, "{}", e),
            _ => f.write_str(self.description()),
        }

    }
}

impl StdError for Error {
    fn description(&self) -> &str {
        match *self {
            ArchiveNameConflict => "An archive with that name already exists",
            ArchiveNameTooLong => "The archive name must be <= 127 bytes (UTF-8)",
            ArchiveNotFound => "The specified archive was not found",
            Acd(_) => "There was a problem communicating with Amazon Cloud Drive",
            BackendOnDifferentDevices => "All folders in the backend must be on the same drive",
            BadBackendPath(ref e) => e,
            BlockNotFound => "The specified block was not found",
            CorruptArchiveName => "The encrypted archive name is corrupted",
            CorruptArchiveBadBlockSecret => {
                "The archive is corrupted.  One of the block secrets could not be parsed"
            }
            CorruptArchiveBadHmac => "The encrypted archive is corrupt: Bad Hmac",
            CorruptArchiveBadJson => {
                "The encrypted archive is corrupt: the internal JSON data is invalid"
            }
            CorruptArchiveFailedDecompression => {
                "The encrypted archive is corrupt: could not be decompressed"
            }
            CorruptArchiveNotUtf8 => "The encrypted archive is corrupt: data is not UTF-8",
            CorruptArchiveTruncated => "The encrypted archive is corrupted: Truncated",
            CorruptBlock => "The encrypted block is corrupted",
            #[cfg(feature = "gluster")]
            GlusterError(ref e) => e.description(),
            InvalidArchiveName => {
                "An invalid archive name was encountered.  Possibly a stray file."
            }
            Io(ref e) => e.description(),
            JsonDecoder(_) => "Invalid JSON",
            #[cfg(feature = "ceph")]
            RadosError(ref e) => e.description(),
            Sqlite(ref e) => e.description(),
            VaultError(ref e) => e.description(),
            FromUtf8Error(ref e) => e.description(),
        }
    }

    fn cause(&self) -> Option<&StdError> {
        match *self {
            Acd(ref error) => Some(error),
            ArchiveNameConflict => None,
            ArchiveNameTooLong => None,
            ArchiveNotFound => None,
            BadBackendPath(_) => None,
            BackendOnDifferentDevices => None,
            BlockNotFound => None,
            CorruptArchiveName => None,
            CorruptArchiveBadBlockSecret => None,
            CorruptArchiveBadJson => None,
            CorruptArchiveBadHmac => None,
            CorruptArchiveFailedDecompression => None,
            CorruptArchiveNotUtf8 => None,
            CorruptArchiveTruncated => None,
            CorruptBlock => None,
            InvalidArchiveName => None,
            Io(ref error) => Some(error),
            JsonDecoder(ref error) => Some(error),
            #[cfg(feature = "gluster")]
            GlusterError(ref error) => Some(error),
            VaultError(ref error) => Some(error),
            #[cfg(feature = "ceph")]
            RadosError(ref error) => Some(error),
            Sqlite(ref error) => Some(error),
            FromUtf8Error(ref error) => Some(error),
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

impl From<AcdError> for Error {
    fn from(err: AcdError) -> Error {
        Acd(err)
    }
}

#[cfg(feature = "ceph")]
impl From<::ceph_rust::ceph::RadosError> for Error {
    fn from(err: ::ceph_rust::ceph::RadosError) -> Error {
        RadosError(err)
    }
}

#[cfg(feature = "gluster")]
impl From<::gfapi_sys::gluster::GlusterError> for Error {
    fn from(err: ::gfapi_sys::gluster::GlusterError) -> Error {
        GlusterError(err)
    }
}

impl From<::vault::Error> for Error {
    fn from(err: ::vault::Error) -> Error {
        VaultError(err)
    }
}

impl From<SqliteError> for Error {
    fn from(err: SqliteError) -> Error {
        Sqlite(err)
    }
}

impl From<::std::string::FromUtf8Error> for Error {
    fn from(err: ::std::string::FromUtf8Error) -> Error {
        FromUtf8Error(err)
    }
}
