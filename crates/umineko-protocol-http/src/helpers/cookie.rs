use alloc::{string::String, vec::Vec};
use crate::errors::HTTPError;

use umineko_url::URL;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HTTPCookieSameSite {
    Strict,
    Lax,
    None,
}

impl HTTPCookieSameSite {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Strict => "Strict",
            Self::Lax => "Lax",
            Self::None => "None",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct HTTPCookie {
    pub name: String,
    pub value: String,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub expires: Option<f64>,
    pub max_age: Option<i64>,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<HTTPCookieSameSite>,
}

impl HTTPCookie {
    pub fn new(name: &str, value: &str) -> Self {
        todo!()
    }

    pub fn encode(&self) -> String {
        todo!()
    }

    pub fn decode(text: &str) -> Result<Self, HTTPError> {
        todo!()
    }

    pub fn matches(&self, url: &URL) -> bool {
        todo!()
    }

    pub fn expired(&self, now: f64) -> bool {
        todo!()
    }

    pub fn session(&self) -> bool {
        self.expires.is_none() && self.max_age.is_none()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct HTTPCookies {
    cookies: Vec<HTTPCookie>,
}

impl HTTPCookies {
    pub fn new() -> Self {
        todo!()
    }

    pub fn insert(&mut self, url: &URL, cookie: HTTPCookie) -> Result<(), HTTPError> {
        todo!()
    }

    pub fn remove(&mut self, name: &str) {
        todo!()
    }

    pub fn get(&self, url: &URL) -> Vec<&HTTPCookie> {
        todo!()
    }

    pub fn encode(&self, url: &URL) -> Option<String> {
        todo!()
    }

    pub fn expire(&mut self, now: f64) -> usize {
        todo!()
    }

    pub fn clear(&mut self) {
        todo!()
    }

    pub fn len(&self) -> usize {
        todo!()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for HTTPCookies {
    fn default() -> Self {
        Self::new()
    }
}
