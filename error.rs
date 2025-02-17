use core::fmt::Debug;
use core::fmt::Display;
use core::num::TryFromIntError;

#[derive(Debug)]
pub struct Error {
    pub context: &'static str,
    pub kind: Kind,
}

#[derive(Debug)]
pub enum Kind {
    Conversion,
    Unsupported,
    Unknown,
    General,
}

impl Error {
    #[must_use]
    pub fn new(context: &'static str, kind: Kind) -> Self {
        Self { context, kind }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[{}] {}", self.context, self.kind)
    }
}

impl From<TryFromIntError> for Error {
    fn from(_: TryFromIntError) -> Self {
        Error::new("Integer conversion failed", Kind::Conversion)
    }
}

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
