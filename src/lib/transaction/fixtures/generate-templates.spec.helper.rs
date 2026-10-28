//! Port of `transaction/fixtures/generate-templates.spec.helper.ts`: print the
//! JSON of an example wallet template
//! (`cargo run --example generate-templates -- <template>`).
//!
//! Port addition: `cargo run --example generate-templates -- --write <directory>`
//! writes every template to `<directory>/<template>.json` exactly as libauth's
//! `yarn gen:templates` writes `transaction/fixtures/templates/*.json`: this
//! script's output (`console.log(stringify(template))`) followed by
//! `prettier --write` (emulated by [`format_json_like_prettier`]).
//!
//! The Rust `WalletTemplate` is a struct, so templates are converted with
//! `Json::from`, which writes keys in sorted order like libauth's literals;
//! [`name_first`]
//! reproduces the `...{ name: '...' }` spread with which some of libauth's
//! templates place `name` first.
#![allow(dead_code)]

#[path = "template.2-of-2-recoverable.spec.helper.rs"]
mod template_2_of_2_recoverable_spec_helper;
#[path = "template.2-of-3.spec.helper.rs"]
mod template_2_of_3_spec_helper;
#[path = "template.cash-channels-v1.spec.helper.rs"]
mod template_cash_channels_v1_spec_helper;
#[path = "template.sig-of-sig.spec.helper.rs"]
mod template_sig_of_sig_spec_helper;

use std::path::Path;

use libauth::runtime::json::{encode_json, parse_json, Json};
use libauth::{stringify, walletTemplateP2pkh};

use template_2_of_2_recoverable_spec_helper::twoOfTwoRecoverable;
use template_2_of_3_spec_helper::twoOfThree;
use template_cash_channels_v1_spec_helper::cashChannels;
use template_sig_of_sig_spec_helper::sigOfSig;

/// The template identifiers accepted by [`print_template`] (in the order used
/// by `yarn gen:templates`).
pub const TEMPLATES: [&str; 5] = [
    "p2pkh",
    "2-of-3",
    "2-of-2-recoverable",
    "sig-of-sig",
    "cash-channels-v1",
];

/// Move the `name` property to the front of a template object (libauth's
/// `{ ...{ name: '...' }, ... }`).
fn name_first(json: Json) -> Json {
    let Json::Object(mut entries) = json else {
        unreachable!("templates are objects")
    };
    if let Some(index) = entries.iter().position(|(key, _)| key == "name") {
        let name = entries.remove(index);
        entries.insert(0, name);
    }
    Json::Object(entries)
}

/// `printTemplate`: the text logged for `template` (`stringify(template)`), or
/// `None` for an unknown template.
pub fn print_template(template: &str) -> Option<String> {
    let json = match template {
        "p2pkh" => Json::from(&*walletTemplateP2pkh),
        "2-of-3" => name_first(Json::from(&*twoOfThree)),
        "2-of-2-recoverable" => name_first(Json::from(&*twoOfTwoRecoverable)),
        "sig-of-sig" => name_first(Json::from(&*sigOfSig)),
        "cash-channels-v1" => Json::from(&*cashChannels),
        _ => return None,
    };
    Some(stringify(&json, None))
}

/// Prettier's default `printWidth`.
const PRINT_WIDTH: usize = 80;

fn is_primitive(value: &Json) -> bool {
    match value {
        Json::Array(items) => items.is_empty(),
        Json::Object(entries) => entries.is_empty(),
        _ => true,
    }
}

/// Format `value` starting at column `column` of a line indented by
/// `indent`, followed on its last line by `suffix` characters (a comma).
fn format_value(value: &Json, indent: usize, column: usize, suffix: usize) -> String {
    match value {
        // Objects are expanded in the input (as printed by `stringify`), and
        // prettier preserves expanded objects.
        Json::Object(entries) if !entries.is_empty() => {
            let inner = " ".repeat(indent + 2);
            let lines: Vec<String> = entries
                .iter()
                .enumerate()
                .map(|(index, (key, item))| {
                    let key = encode_json(&Json::String(key.clone()));
                    let comma = usize::from(index + 1 < entries.len());
                    format!(
                        "{inner}{key}: {}{}",
                        format_value(item, indent + 2, indent + 2 + key.chars().count() + 2, comma),
                        if comma == 1 { "," } else { "" }
                    )
                })
                .collect();
            format!("{{\n{}\n{}}}", lines.join("\n"), " ".repeat(indent))
        }
        // Arrays are printed on one line when they fit within the print width.
        Json::Array(items) if !items.is_empty() => {
            let flat = format!("[{}]", items.iter().map(encode_json).collect::<Vec<_>>().join(", "));
            if items.iter().all(is_primitive) && column + flat.chars().count() + suffix <= PRINT_WIDTH {
                return flat;
            }
            let inner = " ".repeat(indent + 2);
            let lines: Vec<String> = items
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    let comma = usize::from(index + 1 < items.len());
                    format!(
                        "{inner}{}{}",
                        format_value(item, indent + 2, indent + 2, comma),
                        if comma == 1 { "," } else { "" }
                    )
                })
                .collect();
            format!("[\n{}\n{}]", lines.join("\n"), " ".repeat(indent))
        }
        other => encode_json(other),
    }
}

/// Format JSON text as `prettier --write` (v3, `printWidth: 80`) formats the
/// output of this script: expanded objects remain expanded, and arrays of
/// primitives are collapsed onto one line if they fit.
pub fn format_json_like_prettier(json_text: &str) -> String {
    let value = parse_json(json_text).expect("stringify produces valid JSON");
    format!("{}\n", format_value(&value, 0, 0, 0))
}

/// Port addition: write each template to `<directory>/<template>.json`, as
/// `yarn gen:templates` does.
pub fn write_templates(directory: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(directory)?;
    for template in TEMPLATES {
        // `node generate-templates.spec.helper.js <template> > <template>.json`
        let logged = format!("{}\n", print_template(template).expect("known template"));
        // `prettier 'src/lib/transaction/fixtures/templates/*.json' --write`
        std::fs::write(
            directory.join(format!("{template}.json")),
            format_json_like_prettier(&logged),
        )?;
    }
    Ok(())
}

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.as_slice() {
        [flag, directory] if flag == "--write" => {
            if let Err(error) = write_templates(Path::new(directory)) {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
        [template] => match print_template(template) {
            Some(text) => println!("{text}"),
            None => {
                eprintln!("unknown template");
                std::process::exit(1);
            }
        },
        _ => {
            eprintln!("unknown template");
            std::process::exit(1);
        }
    }
}
