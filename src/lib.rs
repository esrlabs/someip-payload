//! Crate for parsing SOME/IP payload.

#![deny(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

#[macro_use]
extern crate log;

pub mod fibex;
pub mod fibex2som;
pub mod som;

#[doc(hidden)]
mod som2text;
