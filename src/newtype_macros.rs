/*
Copied and modified from github.com/dnaq/sodiumoxide

Copyright (c) 2015 The sodiumoxide Developers

License: MIT OR Apache-2.0
*/


macro_rules! newtype_clone (($newtype:ident) => (
        impl Clone for $newtype {
            fn clone(&self) -> $newtype {
                let &$newtype(v) = self;
                $newtype(v)
            }
        }

        ));

macro_rules! newtype_from_slice (($newtype:ident, $len:expr) => (
    /// `from_slice()` creates an object from a byte slice
    ///
    /// This function will fail and return `None` if the length of
    /// the byte-slice isn't equal to the length of the object
    pub fn from_slice(bs: &[u8]) -> Option<$newtype> {
        if bs.len() != $len {
            return None;
        }
        let mut n = $newtype([0; $len]);
        for (ni, &bsi) in n.0.iter_mut().zip(bs.iter()) {
            *ni = bsi
        }
        Some(n)
    }

	pub fn from_rng(rng: &mut ::rand::rngs::OsRng) -> $newtype {
        use rand::RngCore;
		let mut n = $newtype([0; $len]);
		{
			let $newtype(ref mut b) = n;
			rng.fill_bytes(b);
		}
		n
	}
));

macro_rules! newtype_traits (($newtype:ident, $len:expr) => (
    impl ::std::cmp::PartialEq for $newtype {
        fn eq(&self, &$newtype(ref other): &$newtype) -> bool {
			use crypto::util::fixed_time_eq;
            let &$newtype(ref this) = self;
			fixed_time_eq(this, other)
        }
    }

    impl ::std::cmp::Eq for $newtype {}

    impl ::serde::Serialize for $newtype {
        fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
            where S: ::serde::Serializer
        {
            use ::data_encoding::HEXLOWER_PERMISSIVE;
            serializer.serialize_str(&HEXLOWER_PERMISSIVE.encode(&self[..]))
        }
    }

    impl<'de> ::serde::Deserialize<'de> for $newtype {
        fn deserialize<D>(deserializer: D) -> ::std::result::Result<$newtype, D::Error>
            where D: ::serde::Deserializer<'de>
        {
            struct NewtypeVisitor;
            impl<'de> ::serde::de::Visitor<'de> for NewtypeVisitor {
                type Value = $newtype;
                fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                    write!(formatter, stringify!($newtype))
                }

                fn visit_str<E>(self, v: &str) -> ::std::result::Result<Self::Value, E>
                    where E: ::serde::de::Error
                {
                    use ::data_encoding::HEXLOWER_PERMISSIVE;
                    let slice = HEXLOWER_PERMISSIVE.decode(v.as_bytes()).map_err(::serde::de::Error::custom)?;
                    $newtype::from_slice(&slice).ok_or(::serde::de::Error::invalid_length(slice.len(), &self))
                }
            }

            deserializer.deserialize_str(NewtypeVisitor)
        }
    }

    /// Allows a user to access the byte contents of an object as a slice.
    ///
    /// WARNING: it might be tempting to do comparisons on objects
    /// by using `x[a..b] == y[a..b]`. This will open up for timing attacks
    /// when comparing for example authenticator tags. Because of this only
    /// use the comparison functions exposed by the sodiumoxide API.
    impl ::std::ops::Index<::std::ops::Range<usize>> for $newtype {
        type Output = [u8];
        fn index(&self, _index: ::std::ops::Range<usize>) -> &[u8] {
            self.0.index(_index)
        }
    }
    /// Allows a user to access the byte contents of an object as a slice.
    ///
    /// WARNING: it might be tempting to do comparisons on objects
    /// by using `x[..b] == y[..b]`. This will open up for timing attacks
    /// when comparing for example authenticator tags. Because of this only
    /// use the comparison functions exposed by the sodiumoxide API.
    impl ::std::ops::Index<::std::ops::RangeTo<usize>> for $newtype {
        type Output = [u8];
        fn index(&self, _index: ::std::ops::RangeTo<usize>) -> &[u8] {
            self.0.index(_index)
        }
    }
    /// Allows a user to access the byte contents of an object as a slice.
    ///
    /// WARNING: it might be tempting to do comparisons on objects
    /// by using `x[a..] == y[a..]`. This will open up for timing attacks
    /// when comparing for example authenticator tags. Because of this only
    /// use the comparison functions exposed by the sodiumoxide API.
    impl ::std::ops::Index<::std::ops::RangeFrom<usize>> for $newtype {
        type Output = [u8];
        fn index(&self, _index: ::std::ops::RangeFrom<usize>) -> &[u8] {
            self.0.index(_index)
        }
    }
    /// Allows a user to access the byte contents of an object as a slice.
    ///
    /// WARNING: it might be tempting to do comparisons on objects
    /// by using `x[] == y[]`. This will open up for timing attacks
    /// when comparing for example authenticator tags. Because of this only
    /// use the comparison functions exposed by the sodiumoxide API.
    impl ::std::ops::Index<::std::ops::RangeFull> for $newtype {
        type Output = [u8];
        fn index(&self, _index: ::std::ops::RangeFull) -> &[u8] {
            self.0.index(_index)
        }
    }

    impl ::std::fmt::Debug for $newtype  {
        fn fmt(&self,
               formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
            write!(formatter, "{}({:?})", stringify!($newtype), &self[..])
        }
    }
    ));

macro_rules! public_newtype_traits (($newtype:ident) => (
    impl AsRef<[u8]> for $newtype {
        #[inline]
        fn as_ref(&self) -> &[u8] {
            &self[..]
        }
    }
    impl ::std::cmp::PartialOrd for $newtype {
        #[inline]
        fn partial_cmp(&self,
                       other: &$newtype) -> Option<::std::cmp::Ordering> {
            ::std::cmp::PartialOrd::partial_cmp(self.as_ref(), other.as_ref())
        }
        #[inline]
        fn lt(&self, other: &$newtype) -> bool {
            ::std::cmp::PartialOrd::lt(self.as_ref(), other.as_ref())
        }
        #[inline]
        fn le(&self, other: &$newtype) -> bool {
            ::std::cmp::PartialOrd::le(self.as_ref(), other.as_ref())
        }
        #[inline]
        fn ge(&self, other: &$newtype) -> bool {
            ::std::cmp::PartialOrd::ge(self.as_ref(), other.as_ref())
        }
        #[inline]
        fn gt(&self, other: &$newtype) -> bool {
            ::std::cmp::PartialOrd::gt(self.as_ref(), other.as_ref())
        }
    }
    impl ::std::cmp::Ord for $newtype {
        #[inline]
        fn cmp(&self, other: &$newtype) -> ::std::cmp::Ordering {
            ::std::cmp::Ord::cmp(self.as_ref(), other.as_ref())
        }
    }
    impl ::std::hash::Hash for $newtype {
        fn hash<H: ::std::hash::Hasher>(&self, state: &mut H) {
            ::std::hash::Hash::hash(self.as_ref(), state)
        }
    }
    ));

/// Macro used for generating newtypes of byte-arrays
///
/// Usage:
/// Generating secret datatypes, e.g. keys
/// new_type! {
///     /// This is some documentation for our type
///     secret Key(KEYBYTES);
/// }
/// Generating public datatypes, e.g. public keys
/// ```
/// new_type! {
///     /// This is some documentation for our type
///     public PublicKey(PUBLICKEYBYTES);
/// }
/// ```
macro_rules! new_type {
    ( $(#[$meta:meta])*
      secret $name:ident($bytes:expr);
      ) => (
        $(#[$meta])*
        #[must_use]
        pub struct $name(pub [u8; $bytes]);
        newtype_clone!($name);
        newtype_traits!($name, $bytes);
        impl $name {
            newtype_from_slice!($name, $bytes);
        }
        impl Drop for $name {
            fn drop(&mut self) {
				use crypto::util::secure_memset;
                let &mut $name(ref mut v) = self;
				secure_memset(v, 0);
            }
        }
        );
    ( $(#[$meta:meta])*
      public $name:ident($bytes:expr);
      ) => (
        $(#[$meta])*
        #[derive(Copy)]
        #[must_use]
        pub struct $name(pub [u8; $bytes]);
        newtype_clone!($name);
        newtype_traits!($name, $bytes);
        public_newtype_traits!($name);
        impl $name {
            newtype_from_slice!($name, $bytes);
        }
        );
}
