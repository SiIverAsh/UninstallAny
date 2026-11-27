use std::{env, ffi::OsString};

const LOCALE_VARIABLES: &[&str] = &["LC_ALL", "LC_MESSAGES", "LANG"];

/// Language used for this CLI invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Locale {
    English,
    Chinese,
}

impl Locale {
    pub(crate) fn from_environment() -> Self {
        Self::from_preferences(LOCALE_VARIABLES.iter().filter_map(env::var_os))
    }

    fn from_preferences(values: impl IntoIterator<Item = OsString>) -> Self {
        let preference = values.into_iter().find(|value| !value.is_empty());
        let is_chinese = preference
            .as_deref()
            .and_then(|value| value.to_str())
            .and_then(|value| value.split(['_', '-', '.', '@']).next())
            .is_some_and(|language| language.eq_ignore_ascii_case("zh"));
        if is_chinese {
            Self::Chinese
        } else {
            Self::English
        }
    }

    pub(crate) fn text<'a>(self, en: &'a str, zh: &'a str) -> &'a str {
        match self {
            Self::English => en,
            Self::Chinese => zh,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Locale;

    #[test]
    fn first_nonempty_locale_controls_cli_language() {
        let select = |preferences: &[&str]| {
            Locale::from_preferences(preferences.iter().copied().map(Into::into))
        };
        assert_eq!(select(&["", "zh_CN.UTF-8", "C"]), Locale::Chinese);
        assert_eq!(select(&["C.UTF-8", "zh_CN.UTF-8"]), Locale::English);
        assert_eq!(select(&["zh-Hant"]), Locale::Chinese);
        assert_eq!(select(&["zho_FAKE"]), Locale::English);
        assert_eq!(select(&[]), Locale::English);
    }
}
