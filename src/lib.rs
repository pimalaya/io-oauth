#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![doc = include_str!("../README.md")]

#[cfg(feature = "oauth2")]
#[path = "2.0/mod.rs"]
pub mod v2_0;
