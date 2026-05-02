use passkeyd_abi::config;
use std::borrow::Cow;
use std::{env, ffi::OsStr};

rust_i18n::i18n!("locales", fallback = "en");

pub use rust_i18n::t;

const LANGUAGE: &str = "LANGUAGE";
const LC_ALL: &str = "LC_ALL";
const LC_MESSAGES: &str = "LC_MESSAGES";
const LANG: &str = "LANG";

pub fn translate_key(key: &str) -> Cow<'static, str> {
    Cow::Owned(rust_i18n::t!(key).into_owned())
}

pub fn translate_key_with_vars(key: &str, vars: &[(&str, &str)]) -> Cow<'static, str> {
    let mut translated = rust_i18n::t!(key).into_owned();
    for (name, value) in vars {
        let pattern = format!("%{{{}}}", name);
        translated = translated.replace(&pattern, value);
    }
    Cow::Owned(translated)
}

#[macro_export]
macro_rules! translate {
    ($key:expr) => {
        $crate::translate_key($key)
    };
    ($key:expr, $($name:ident => $value:expr),+) => {
        $crate::translate_key_with_vars($key, &[
            $( (stringify!($name), &$value.to_string()) ),+
        ])
    };
}

pub fn init_translations() {
    let config = config::Config::initialize().expect("Failed to load config");
    let mut locales = get_locale(&StdEnv);
    let best_match = locales.next().unwrap_or_else(|| "en".to_string());
    if let Some(lang) = config.lang {
        rust_i18n::set_locale(&lang);
    } else {
        rust_i18n::set_locale(&best_match);
    }
}

// Based on https://docs.rs/sys-locale/latest/src/sys_locale/unix.rs.html
trait EnvAccess {
    fn get(&self, key: impl AsRef<OsStr>) -> Option<String>;
}

struct StdEnv;
impl EnvAccess for StdEnv {
    fn get(&self, key: impl AsRef<OsStr>) -> Option<String> {
        env::var(key).ok()
    }
}

fn get_locale(env: &impl EnvAccess) -> impl Iterator<Item = String> {
    let mut locales = Vec::new();

    if let Some(val) = env.get(LANGUAGE).filter(|val| !val.is_empty()) {
        for part in val.split(':') {
            let locale = posix_to_bcp47(part);
            if !locales.contains(&locale) {
                locales.push(locale);
            }
        }
    }

    for variable in [LC_ALL, LC_MESSAGES, LANG] {
        if let Some(val) = env.get(variable).filter(|val| !val.is_empty()) {
            let locale = posix_to_bcp47(&val);
            if !locales.contains(&locale) {
                locales.push(locale);
            }
        }
    }

    locales.into_iter()
}

fn posix_to_bcp47(locale: &str) -> String {
    // locale
    //     .chars()
    //     .take_while(|&c| c != '.' && c != '@')
    //     .map(|c| if c == '_' { '-' } else { c })
    //     .collect()

    locale
        .chars()
        .take_while(|&c| c != '.' && c != '@' && c != '_' && c != '-')
        .collect()
}
