use core::fmt::{Debug, Display};
use core::num::TryFromIntError;

/// Structure, representing an error.
#[derive(Debug)]
pub struct Error {
    /// The context of the error.
    pub context: &'static str,
    /// The error's kind.
    pub kind: Kind,
}

/// Enumerates different types of errors that can occur.
#[derive(Debug)]
pub enum Kind {
    /// Error related to type conversion failures.
    Conversion,
    /// Error indicating an unsupported operation, value or feature.
    Unsupported,
    /// Error caused by an unknown value.
    Unknown,
    /// A general-purpose error category.
    General,
}

impl Error {
    /// Creates a new `Error` instance.
    ///
    /// # Arguments:
    ///
    /// * `context` - A description of where the error occurred.
    /// * `kind` - The specific kind of error.
    #[must_use]
    pub fn new(context: &'static str, kind: Kind) -> Self {
        Self { context, kind }
    }
}

// We need to implement a [Display] trait to be able print the error.
impl Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[{}] {}", self.context, self.kind)
    }
}

// A sample implementation of the conversion of the error of a different type.
impl From<TryFromIntError> for Error {
    fn from(_: TryFromIntError) -> Self {
        Error::new("integer conversion failed", Kind::Conversion)
    }
}

// We need to implement a [Display] trait to be able print the Kind of the error.
impl Display for Kind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self {
            Kind::Conversion => write!(f, "conversion error"),
            Kind::Unsupported => write!(f, "unsupported error"),
            Kind::Unknown => write!(f, "unknown value error"),
            Kind::General => write!(f, "general error"),
        }
    }
}
