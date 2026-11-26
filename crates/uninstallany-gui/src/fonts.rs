use std::thread;

use eframe::egui::{Context, FontData, FontDefinitions, FontFamily};
use eframe::epaint::text::{FontInsert, FontPriority, InsertFontFamily};
use fontdb::{Database, Family, ID, Query, Weight};
use ttf_parser::Face;

const UI_REGULAR_NAME: &str = "system-ui-regular";
const UI_SEMIBOLD_NAME: &str = "system-ui-semibold";
pub(crate) const SEMIBOLD_FAMILY: &str = "semibold";

const PREFERRED_FONT_BYTES: usize = 24 * 1024 * 1024;
const MAX_FONT_BYTES: usize = 96 * 1024 * 1024;
const CHINESE_LABEL_SAMPLE: &str = "应用卸载清理文件注册表还原确认。";
const CHINESE_FAMILIES: &[&str] = &[
    "Microsoft YaHei UI",
    "Microsoft YaHei",
    "PingFang SC",
    "Hiragino Sans GB",
    "Noto Sans CJK SC",
    "Noto Sans SC",
    "Source Han Sans SC",
    "DengXian",
    "WenQuanYi Micro Hei",
    "Heiti SC",
    "SimHei",
    "SimSun",
    "Songti SC",
];

/// Returns the custom semibold font family registered at startup.
pub(crate) fn semibold_family() -> FontFamily {
    FontFamily::Name(SEMIBOLD_FAMILY.into())
}

/// Ensures the named `semibold` family exists immediately from frame 0
/// (falling back to built-in proportional fonts until system fonts finish loading).
pub(crate) fn register_initial_families(context: &Context) {
    let mut defs = FontDefinitions::default();
    let base = defs
        .families
        .get(&FontFamily::Proportional)
        .cloned()
        .unwrap_or_default();
    defs.families.insert(semibold_family(), base);
    context.set_fonts(defs);
}

/// Loads unified system CJK+Latin Regular and Semibold UI fonts synchronously (used by tests).
#[cfg(test)]
pub(crate) fn load_sync_for_test(context: &Context) -> Option<String> {
    let mut database = Database::new();
    database.load_system_fonts();
    let (family_name, regular, semibold) = select_font_pair_named(&database)?;
    apply_font_pair(context, regular, semibold);
    Some(family_name.to_owned())
}

/// Loads unified system CJK+Latin Regular and Semibold UI fonts off the UI thread.
pub(crate) fn load_in_background(context: Context) {
    let discovery = thread::Builder::new()
        .name("system-font-discovery".into())
        .spawn(move || {
            let mut database = Database::new();
            database.load_system_fonts();
            let Some((_, regular, semibold)) = select_font_pair_named(&database) else {
                return;
            };
            apply_font_pair(&context, regular, semibold);
            context.request_repaint();
        });

    if let Err(error) = discovery {
        eprintln!("Could not start local font discovery ({error}).");
    }
}

fn apply_font_pair(context: &Context, regular: FontData, semibold: Option<FontData>) {
    // Insert Regular at Highest priority for Proportional so Latin, digits,
    // punctuation, and Chinese share one unified baseline and metric set.
    // Keep Lowest priority for Monospace so code/UUIDs retain crisp mono Latin.
    context.add_font(FontInsert {
        name: UI_REGULAR_NAME.into(),
        data: regular,
        families: vec![
            InsertFontFamily {
                family: FontFamily::Proportional,
                priority: FontPriority::Highest,
            },
            InsertFontFamily {
                family: semibold_family(),
                priority: FontPriority::Highest,
            },
            InsertFontFamily {
                family: FontFamily::Monospace,
                priority: FontPriority::Lowest,
            },
        ],
    });

    if let Some(bold_face) = semibold {
        context.add_font(FontInsert {
            name: UI_SEMIBOLD_NAME.into(),
            data: bold_face,
            families: vec![InsertFontFamily {
                family: semibold_family(),
                priority: FontPriority::Highest,
            }],
        });
    }
}

fn select_font_pair_named(database: &Database) -> Option<(&'static str, FontData, Option<FontData>)> {
    let mut larger_candidate: Option<(&'static str, ID, usize)> = None;
    for family in CHINESE_FAMILIES {
        let Some(id) = query_weight(database, family, Weight::NORMAL) else {
            continue;
        };
        let Some(size) = database.with_face_data(id, chinese_font_size).flatten() else {
            continue;
        };
        if size <= PREFERRED_FONT_BYTES {
            if let Some(regular) = copy_font(database, id) {
                let semibold = select_semibold(database, family, id);
                return Some((family, regular, semibold));
            }
        } else if larger_candidate.is_none_or(|(_, _, previous_size)| size < previous_size) {
            larger_candidate = Some((family, id, size));
        }
    }
    larger_candidate.and_then(|(family, id, _)| {
        let regular = copy_font(database, id)?;
        let semibold = select_semibold(database, family, id);
        Some((family, regular, semibold))
    })
}

fn query_weight(database: &Database, family: &str, weight: Weight) -> Option<ID> {
    database.query(&Query {
        families: &[Family::Name(family)],
        weight,
        ..Query::default()
    })
}

fn select_semibold(database: &Database, family: &str, regular_id: ID) -> Option<FontData> {
    for weight in [Weight::SEMIBOLD, Weight::BOLD, Weight::MEDIUM] {
        let Some(id) = query_weight(database, family, weight) else {
            continue;
        };
        if id == regular_id {
            continue;
        }
        if let Some(font) = copy_font(database, id) {
            return Some(font);
        }
    }
    None
}

fn chinese_font_size(data: &[u8], index: u32) -> Option<usize> {
    if data.len() > MAX_FONT_BYTES {
        return None;
    }
    let face = Face::parse(data, index).ok()?;
    let has_label_glyphs = CHINESE_LABEL_SAMPLE
        .chars()
        .all(|character| face.glyph_index(character).is_some());
    has_label_glyphs.then_some(data.len())
}

fn copy_font(database: &Database, id: ID) -> Option<FontData> {
    database
        .with_face_data(id, |data, index| {
            chinese_font_size(data, index)?;
            Some(FontData {
                index,
                ..FontData::from_owned(data.to_vec())
            })
        })
        .flatten()
}

#[cfg(test)]
mod tests {
    use eframe::egui::FontDefinitions;

    use super::chinese_font_size;

    #[test]
    fn rejects_builtin_faces_without_chinese_label_glyphs() {
        let fonts = FontDefinitions::default();
        assert!(!fonts.font_data.is_empty());
        assert!(
            fonts
                .font_data
                .values()
                .all(|font| { chinese_font_size(font.font.as_ref(), font.index).is_none() })
        );
    }
}
