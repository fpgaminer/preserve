use std::error::Error as StdError;
use std::io::Error as IoError;
use rustc_serialize::json::DecoderError as JsonDecoderError;
use acd::Error as AcdError;
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
    Acd(AcdError),
    #[cfg(feature = "ceph")]
    RadosError(::ceph_rust::ceph::RadosError),
    #[cfg(feature = "gluster")]
    GlusterError(::gfapi_sys::gluster::GlusterError),
    BlockNotFound,
    ArchiveNotFound,
    InvalidArchiveName,
    BackendOnDifferentDevices,
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
            CorruptArchiveFailedDecompression => {
                "The encrypted archive is corrupt: could not be decompressed"
            }
            CorruptArchiveNotUtf8 => "The encrypted archive is corrupt: data is not UTF-8",
            CorruptArchiveBadJson => {
                "The encrypted archive is corrupt: the internal JSON data is invalid"
            }
            CorruptBlock => "The encrypted block is corrupted",
            Acd(_) => "There was a problem communicating with Amazon Cloud Drive",
            #[cfg(feature = "ceph")]
            RadosError(ref e) => e.description(),
            #[cfg(feature = "gluster")]
            GlusterError(ref e) => e.description(),
            BlockNotFound => "The specified block was not found",
            ArchiveNotFound => "The specified archive was not found",
            InvalidArchiveName => {
                "An invalid archive name was encountered.  Possibly a stray file."
            }
            ArchiveNameConflict => "An archive with that name already exists",
            BackendOnDifferentDevices => "All folders in the backend must be on the same drive",
            CorruptArchiveBadBlockSecret => {
                "The archive is corrupted.  One of the block secrets could not be parsed"
            }
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
            Acd(ref error) => Some(error),
            #[cfg(feature = "gluster")]
            GlusterError(ref error) => Some(error),
            #[cfg(feature = "ceph")]
            RadosError(ref error) => Some(error),
            ArchiveNameConflict => None,
            BlockNotFound => None,
            InvalidArchiveName => None,
            ArchiveNotFound => None,
            BackendOnDifferentDevices => None,
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
