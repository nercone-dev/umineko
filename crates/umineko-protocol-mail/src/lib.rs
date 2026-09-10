//! Mail authentication.

#![no_std]

extern crate alloc;

#[cfg(feature = "spf")]
pub mod spf;
#[cfg(feature = "dkim")]
pub mod dkim;
#[cfg(feature = "dmarc")]
pub mod dmarc;
#[cfg(feature = "bimi")]
pub mod bimi;

pub mod errors;
pub mod types;

pub use errors::{MailError};
pub use types::{MailResult, MailIdentity, MailLimits};

#[cfg(feature = "spf")]
pub use spf::{SPF, SPFMechanism, SPFQualifier};
#[cfg(feature = "dkim")]
pub use dkim::{DKIM, DKIMSigner, DKIMVerifier, DKIMSignature, DKIMCanonicalization};
#[cfg(feature = "dmarc")]
pub use dmarc::{DMARC, DMARCPolicy, DMARCAlignment};
#[cfg(feature = "bimi")]
pub use bimi::{BIMI, BIMIIndicator};
