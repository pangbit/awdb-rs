#![allow(dead_code)]

mod decoder;

mod db;
pub use db::DB;

pub type Error = anyhow::Error;
pub type Result<T> = anyhow::Result<T>;
