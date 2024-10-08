// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

#![allow(unused)]

use std::error::Error as StdError;
use std::fmt::{self, Display, Formatter};
use std::result::Result as StdResult;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Input,
    IOError,
    DataNotEqual,
}

impl ErrorKind {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Input => "Input error",
            Self::IOError => "IO error",
            Self::DataNotEqual => "Data not equal error",
        }
    }
}

impl Display for ErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The standard crate error type
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    pub cause: Option<Box<dyn StdError + Send + Sync + 'static>>,
    pub message: Option<String>,
    // backtrace (when supported)
}

impl Error {
    pub fn from_msg<T: Into<String>>(kind: ErrorKind, msg: T) -> Self {
        Self {
            kind,
            cause: None,
            message: Some(msg.into()),
        }
    }

    pub fn from_opt_msg<T: Into<String>>(kind: ErrorKind, msg: Option<T>) -> Self {
        Self {
            kind,
            cause: None,
            message: msg.map(Into::into),
        }
    }

    #[must_use]
    #[inline]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    #[must_use]
    pub fn with_cause<T: Into<Box<dyn StdError + Send + Sync>>>(mut self, err: T) -> Self {
        self.cause = Some(err.into());
        self
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.kind, &self.message) {
            (ErrorKind::Input, None) => write!(f, "{:?}", self.kind),
            (ErrorKind::Input, Some(msg)) => f.write_str(msg),
            (kind, None) => write!(f, "{kind}"),
            (kind, Some(msg)) => write!(f, "{kind}: {msg}"),
        }?;
        if let Some(ref source) = self.cause {
            write!(f, " [{source}]")?;
        }
        Ok(())
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.cause
            .as_ref()
            .map(|err| unsafe { std::mem::transmute(&**err) })
    }
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind && self.message == other.message
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self {
            kind,
            cause: None,
            message: None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::from(ErrorKind::IOError).with_cause(err)
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Self::from(ErrorKind::Input).with_cause(err)
    }
}

impl From<serde_yaml::Error> for Error {
    fn from(err: serde_yaml::Error) -> Self {
        Self::from(ErrorKind::Input).with_cause(err)
    }
}

impl<M> From<(ErrorKind, M)> for Error
where
    M: fmt::Display + Send + Sync + 'static,
{
    fn from((kind, msg): (ErrorKind, M)) -> Self {
        Self::from_msg(kind, msg.to_string())
    }
}

macro_rules! err_msg {
    () => {
        $crate::error::Error::from($crate::error::ErrorKind::Input)
    };
    ($kind:ident) => {
        $crate::error::Error::from($crate::error::ErrorKind::$kind)
    };
    ($kind:ident, $($args:tt)+) => {
        $crate::error::Error::from_msg($crate::error::ErrorKind::$kind, format!($($args)+))
    };
    ($($args:tt)+) => {
        $crate::error::Error::from_msg($crate::error::ErrorKind::Input, format!($($args)+))
    };
}

macro_rules! err_map {
    ($($params:tt)*) => {
        |err| err_msg!($($params)*).with_cause(err)
    };
}

pub trait ResultExt<T, E> {
    fn map_err_string(self) -> StdResult<T, String>;
    fn map_input_err<F, M>(self, mapfn: F) -> Result<T>
    where
        F: FnOnce() -> M,
        M: fmt::Display + Send + Sync + 'static;
    fn with_err_msg<M>(self, kind: ErrorKind, msg: M) -> Result<T>
    where
        M: fmt::Display + Send + Sync + 'static;
    fn with_input_err<M>(self, msg: M) -> Result<T>
    where
        M: fmt::Display + Send + Sync + 'static;
}

impl<T, E> ResultExt<T, E> for StdResult<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn map_err_string(self) -> StdResult<T, String> {
        self.map_err(|err| err.to_string())
    }

    fn map_input_err<F, M>(self, mapfn: F) -> Result<T>
    where
        F: FnOnce() -> M,
        M: fmt::Display + Send + Sync + 'static,
    {
        self.map_err(|err| Error::from_msg(ErrorKind::Input, mapfn().to_string()).with_cause(err))
    }

    fn with_err_msg<M>(self, kind: ErrorKind, msg: M) -> Result<T>
    where
        M: fmt::Display + Send + Sync + 'static,
    {
        self.map_err(|err| Error::from_msg(kind, msg.to_string()).with_cause(err))
    }

    #[inline]
    fn with_input_err<M>(self, msg: M) -> Result<T>
    where
        M: fmt::Display + Send + Sync + 'static,
    {
        self.map_err(|err| Error::from_msg(ErrorKind::Input, msg.to_string()).with_cause(err))
    }
}

type DynError = Box<dyn StdError + Send + Sync + 'static>;

macro_rules! define_error {
    ($name:tt, $short:expr, $doc:tt) => {
        #[derive(Debug, Error)]
        #[doc=$doc]
        pub struct $name {
            pub context: Option<String>,
            pub source: Option<DynError>,
        }

        impl $name {
            pub fn from_msg<T: Into<String>>(msg: T) -> Self {
                Self::from(msg.into())
            }

            pub fn from_err<E>(err: E) -> Self
            where
                E: StdError + Send + Sync + 'static,
            {
                Self {
                    context: None,
                    source: Some(Box::new(err) as DynError),
                }
            }

            pub fn from_msg_err<M, E>(msg: M, err: E) -> Self
            where
                M: Into<String>,
                E: StdError + Send + Sync + 'static,
            {
                Self {
                    context: Some(msg.into()),
                    source: Some(Box::new(err) as DynError),
                }
            }
        }

        impl From<&str> for $name {
            fn from(context: &str) -> Self {
                Self {
                    context: Some(context.to_owned()),
                    source: None,
                }
            }
        }

        impl From<String> for $name {
            fn from(context: String) -> Self {
                Self {
                    context: Some(context),
                    source: None,
                }
            }
        }

        impl From<Option<String>> for $name {
            fn from(context: Option<String>) -> Self {
                Self {
                    context,
                    source: None,
                }
            }
        }

        impl<M, E> From<(M, E)> for $name
        where
            M: Into<String>,
            E: StdError + Send + Sync + 'static,
        {
            fn from((context, err): (M, E)) -> Self {
                Self::from_msg_err(context, err)
            }
        }

        impl From<$name> for String {
            fn from(s: $name) -> Self {
                s.to_string()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, $short)?;
                match self.context {
                    Some(ref context) => write!(f, ": {}", context),
                    None => Ok(()),
                }
            }
        }
    };
}