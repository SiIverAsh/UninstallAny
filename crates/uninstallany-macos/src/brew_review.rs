//! Read-only effect declarations from a Homebrew installation receipt.

use std::{collections::HashSet, path::Path};

use serde_json::Value;
use uninstallany_core::{
    Access, Cancellation, Category, MatchKind, Proposal, Result, Risk, Scan, Target,
};

use crate::bundle;

const MAX_INSPECTED_ITEMS: usize = 512;
const MAX_ROWS: usize = 96;
const MAX_VALUE_BYTES: usize = 1_024;

/// Adds bounded references from installed `uninstall_artifacts` metadata.
///
/// Homebrew records declarations, which may refer to shared or absent items.
/// The references never enter the filesystem or native-operation pipelines.
pub(super) fn append(
    scan: &mut Scan,
    home: &Path,
    artifacts: &[Value],
    cancel: &Cancellation,
) -> Result<()> {
    let mut review = ReceiptReview {
        scan,
        home,
        cancel,
        seen: HashSet::new(),
        remaining: MAX_INSPECTED_ITEMS,
        unsupported: false,
        limited: false,
    };
    for artifact in artifacts {
        if !review.take_item()? {
            break;
        }
        review.inspect_artifact(artifact)?;
        if review.limited {
            break;
        }
    }
    cancel.check()?;
    if review.unsupported {
        review.scan.warnings.push(
            "The Homebrew receipt contains hooks, scripts, patterns, or unsupported effect declarations outside this literal review.".into(),
        );
    }
    if review.limited {
        review
            .scan
            .warnings
            .push("Homebrew receipt review reached its inspection or display limit.".into());
    }
    Ok(())
}

struct ReceiptReview<'a> {
    scan: &'a mut Scan,
    home: &'a Path,
    cancel: &'a Cancellation,
    seen: HashSet<String>,
    remaining: usize,
    unsupported: bool,
    limited: bool,
}

impl ReceiptReview<'_> {
    fn take_item(&mut self) -> Result<bool> {
        self.cancel.check()?;
        if self.remaining == 0 {
            self.limited = true;
            return Ok(false);
        }
        self.remaining -= 1;
        Ok(true)
    }

    fn inspect_artifact(&mut self, artifact: &Value) -> Result<()> {
        let Some((stanza, arguments)) = artifact
            .as_object()
            .filter(|entry| entry.len() == 1)
            .and_then(|entry| entry.iter().next())
        else {
            self.unsupported = true;
            return Ok(());
        };
        let scope = match stanza.as_str() {
            "uninstall" => "uninstall",
            "zap" => "optional zap",
            "app" => return Ok(()),
            _ => {
                self.unsupported = true;
                return Ok(());
            }
        };
        // Homebrew serializes one map of named arguments inside its DSL args.
        let directives = match arguments.as_array().map(Vec::as_slice) {
            Some([Value::Object(directives)]) => directives,
            Some([]) => return Ok(()),
            Some([Value::String(value)])
                if stanza == "zap"
                    && matches!(value.as_str(), "not_required" | ":not_required") =>
            {
                return Ok(());
            }
            _ => {
                self.unsupported = true;
                return Ok(());
            }
        };
        for (name, value) in directives {
            if !self.take_item()? {
                break;
            }
            if name == "on_upgrade" {
                continue;
            }
            let Some(directive) = Directive::parse(name) else {
                self.unsupported = true;
                continue;
            };
            let values = value
                .as_array()
                .map_or_else(|| std::slice::from_ref(value), Vec::as_slice);
            for value in values {
                if !self.take_item()? {
                    return Ok(());
                }
                self.add_reference(scope, directive, value);
                if self.limited {
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    fn add_reference(&mut self, scope: &str, directive: Directive, value: &Value) {
        let Some(subject) = directive.subject(self.home, value) else {
            self.unsupported = true;
            return;
        };
        let reference = format!("Homebrew {scope} · {} · {subject}", directive.label());
        if self.seen.contains(&reference) {
            return;
        }
        if self.seen.len() == MAX_ROWS {
            self.limited = true;
            return;
        }
        self.seen.insert(reference.clone());
        self.scan.proposals.push(Proposal {
            target: Target::Reference(reference),
            category: directive.category(),
            evidence: MatchKind::RuleHint,
            reason: "declared in the installed Homebrew receipt".into(),
            risk: Risk::High,
            access: Access::ReadOnly("receipt declaration for review only".into()),
        });
    }
}

#[derive(Clone, Copy)]
enum Directive {
    Delete,
    Trash,
    Rmdir,
    Launchctl,
    Pkgutil,
    Quit,
    LoginItem,
}

impl Directive {
    fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "delete" => Self::Delete,
            "trash" => Self::Trash,
            "rmdir" => Self::Rmdir,
            "launchctl" => Self::Launchctl,
            "pkgutil" => Self::Pkgutil,
            "quit" => Self::Quit,
            "login_item" => Self::LoginItem,
            _ => return None,
        })
    }

    fn label(self) -> &'static str {
        match self {
            Self::Delete => "delete path",
            Self::Trash => "trash path",
            Self::Rmdir => "remove empty directory",
            Self::Launchctl => "launchd job",
            Self::Pkgutil => "package receipt pattern",
            Self::Quit => "quit app bundle ID",
            Self::LoginItem => "login item",
        }
    }

    fn category(self) -> Category {
        match self {
            Self::Delete | Self::Trash | Self::Pkgutil => Category::File,
            Self::Rmdir => Category::Directory,
            Self::Launchctl | Self::Quit => Category::Service,
            Self::LoginItem => Category::Startup,
        }
    }

    fn subject(self, home: &Path, value: &Value) -> Option<String> {
        match self {
            Self::Delete | Self::Trash | Self::Rmdir => literal_path(home, value.as_str()?),
            Self::Launchctl | Self::Pkgutil | Self::Quit => {
                let text = value.as_str()?;
                // pkgutil treats its operand as a pattern even if it resembles
                // an identifier. Display the declaration without interpreting it.
                bundle::valid_identifier(text).then(|| text.to_owned())
            }
            Self::LoginItem => {
                if let Some(name) = value.as_str().filter(|name| literal_text(name)) {
                    return Some(name.to_owned());
                }
                let object = value.as_object().filter(|object| object.len() == 1)?;
                literal_path(home, object.get("path")?.as_str()?)
            }
        }
    }
}

fn literal_path(home: &Path, raw: &str) -> Option<String> {
    if !literal_text(raw) {
        return None;
    }
    let (root, relative) = if let Some(relative) = raw.strip_prefix("~/") {
        (home, relative)
    } else {
        (Path::new("/"), raw.strip_prefix('/')?)
    };
    if relative
        .split('/')
        .any(|part| matches!(part, "" | "." | ".."))
    {
        return None;
    }
    root.join(relative).to_str().map(str::to_owned)
}

fn literal_text(raw: &str) -> bool {
    !raw.trim().is_empty()
        && raw.len() <= MAX_VALUE_BYTES
        && !raw.chars().any(|ch| {
            ch.is_control()
                || matches!(
                    ch,
                    '$' | '`' | '\\' | '*' | '?' | '[' | ']' | '{' | '}' |
                    '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
                )
        })
}
