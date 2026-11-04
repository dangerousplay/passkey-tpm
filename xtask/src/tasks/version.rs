//! `cargo xtask version [<new> --summary TEXT [--date YYYY-MM-DD] | --render | --check]`: one
//! place to bump the release version.
//!
//! The version lives in `Cargo.toml` (`[workspace.package] version`) and the release history
//! in `packaging/releases.toml`. Every other file that names the version is rendered from a
//! minijinja template under `packaging/templates/` (`<path>.j2` → `packaging/<path>`), so a
//! bump is: update both sources, refresh the lockfiles, render. `--render` re-renders after a
//! template edit; `--check` renders in memory and fails when a file is out of date (CI gate).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::runner::{cargo, exec, workspace_root, Error, Result};

const RELEASES: &str = "packaging/releases.toml";
const TEMPLATES: &str = "packaging/templates";
const RELEASE_NOTES_TEMPLATE: &str = ".github/release-notes/TEMPLATE.md.j2";
/// Crates of the workspace that the separate fuzz workspace locks by version.
const FUZZ_DEPS: &[&str] = &["passkey-tpm-core", "passkey-tpm-wire"];

/// What `cargo xtask version` was asked to do.
#[derive(Debug, PartialEq, Eq)]
enum Mode {
    Show,
    Check,
    Render,
    Bump {
        version: String,
        summary: String,
        date: Option<String>,
    },
}

fn parse(args: &[String]) -> Result<Mode> {
    let mut version = None;
    let mut summary = None;
    let mut date = None;
    let mut check = false;
    let mut render = false;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let mut value = |flag: &str| {
            it.next()
                .cloned()
                .ok_or_else(|| Error::Msg(format!("{flag} needs a value")))
        };
        match arg.as_str() {
            "--check" => check = true,
            "--render" => render = true,
            "--summary" => summary = Some(value("--summary")?),
            "--date" => date = Some(value("--date")?),
            flag if flag.starts_with('-') => {
                return Err(Error::Msg(format!("unexpected argument `{flag}`")))
            }
            v if version.is_none() => version = Some(v.to_owned()),
            other => return Err(Error::Msg(format!("unexpected argument `{other}`"))),
        }
    }
    let plain = summary.is_none() && date.is_none();
    match (version, check, render) {
        (None, true, false) if plain => Ok(Mode::Check),
        (None, false, true) if plain => Ok(Mode::Render),
        (None, false, false) if plain => Ok(Mode::Show),
        (None, ..) => Err(Error::Msg(
            "use one of: <new> --summary TEXT [--date D], --render, --check".into(),
        )),
        (Some(_), ..) if check || render => {
            Err(Error::Msg("--check and --render take no version".into()))
        }
        (Some(version), ..) => {
            let summary = summary.ok_or_else(|| {
                Error::Msg("a bump needs --summary TEXT (Debian/Fedora changelog line)".into())
            })?;
            Ok(Mode::Bump {
                version,
                summary,
                date,
            })
        }
    }
}

pub fn run(args: &[String]) -> Result {
    let root = workspace_root();
    match parse(args)? {
        Mode::Show => {
            println!("{}", current_version(&root)?);
            Ok(())
        }
        Mode::Check => check(&root),
        Mode::Render => write_rendered(&root),
        Mode::Bump {
            version,
            summary,
            date,
        } => bump(&root, &version, &summary, date),
    }
}

// ------------------------------------------------------------------------------- versions

/// A release version as written in `Cargo.toml` (`0.1.0` or `0.1.0-beta.3`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Version {
    core: String,
    pre: Option<String>,
}

impl Version {
    fn parse(s: &str) -> Result<Self> {
        let (core, pre) = match s.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (s, None),
        };
        let numeric = core.split('.').collect::<Vec<_>>();
        let core_ok = numeric.len() == 3
            && numeric
                .iter()
                .all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
        let pre_ok = pre.is_none_or(|p| {
            !p.is_empty()
                && p.split('.')
                    .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric()))
        });
        if !core_ok || !pre_ok {
            return Err(Error::Msg(format!(
                "`{s}` is not a version like 1.2.3 or 1.2.3-beta.4"
            )));
        }
        Ok(Self {
            core: core.to_owned(),
            pre: pre.map(str::to_owned),
        })
    }

    /// `0.1.0-beta.3` as written in Cargo.toml and git tags.
    fn upstream(&self) -> String {
        match &self.pre {
            Some(pre) => format!("{}-{pre}", self.core),
            None => self.core.clone(),
        }
    }

    /// dpkg and rpm: `~` sorts the pre-release before the final release (`0.1.0~beta.3`).
    fn tilde(&self) -> String {
        match &self.pre {
            Some(pre) => format!("{}~{pre}", self.core),
            None => self.core.clone(),
        }
    }

    /// Arch `pkgver`: no `-`, and the pre-release joined (`0.1.0beta3`).
    fn pkgver(&self) -> String {
        match &self.pre {
            Some(pre) => format!("{}{}", self.core, pre.replace('.', "")),
            None => self.core.clone(),
        }
    }
}

// ----------------------------------------------------------------------------------- dates

/// A calendar date (proleptic Gregorian).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Date {
    year: i64,
    month: u32,
    day: u32,
}

const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

impl Date {
    fn parse(s: &str) -> Result<Self> {
        let bad = || Error::Msg(format!("`{s}` is not a date like 2026-11-04"));
        let mut parts = s.split('-');
        let (Some(y), Some(m), Some(d), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(bad());
        };
        let date = Self {
            year: y.parse().map_err(|_| bad())?,
            month: m.parse().map_err(|_| bad())?,
            day: d.parse().map_err(|_| bad())?,
        };
        if y.len() != 4 || m.len() != 2 || d.len() != 2 || Self::from_days(date.days()) != date {
            return Err(bad());
        }
        Ok(date)
    }

    fn today() -> Self {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        Self::from_days(i64::try_from(secs / 86_400).unwrap_or(0))
    }

    /// Days since 1970-01-01 (H. Hinnant's `days_from_civil`).
    fn days(self) -> i64 {
        let y = if self.month <= 2 {
            self.year - 1
        } else {
            self.year
        };
        let era = y.div_euclid(400);
        let yoe = y.rem_euclid(400);
        let m = i64::from(self.month);
        let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(self.day) - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + doe - 719_468
    }

    /// Inverse of [`Date::days`] (`civil_from_days`).
    fn from_days(days: i64) -> Self {
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = yoe + era * 400 + i64::from(month <= 2);
        Self {
            year,
            month: u32::try_from(month).unwrap_or(1),
            day: u32::try_from(day).unwrap_or(1),
        }
    }

    fn weekday(self) -> &'static str {
        // 1970-01-01 was a Thursday.
        let index = usize::try_from((self.days() + 4).rem_euclid(7)).unwrap_or(0);
        WEEKDAYS.get(index).copied().unwrap_or("Sun")
    }

    fn month_name(self) -> &'static str {
        let index = usize::try_from(self.month.saturating_sub(1)).unwrap_or(0);
        MONTHS.get(index).copied().unwrap_or("Jan")
    }

    fn iso(self) -> String {
        format!("{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }

    /// Debian changelog trailer: `Wed, 04 Nov 2026 00:00:00 +0000`.
    fn debian(self) -> String {
        format!(
            "{}, {:02} {} {} 00:00:00 +0000",
            self.weekday(),
            self.day,
            self.month_name(),
            self.year
        )
    }

    /// RPM `%changelog`: `Wed Nov 04 2026`.
    fn rpm(self) -> String {
        format!(
            "{} {} {:02} {}",
            self.weekday(),
            self.month_name(),
            self.day,
            self.year
        )
    }
}

// --------------------------------------------------------------------------------- sources

/// One entry of `packaging/releases.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Release {
    version: Version,
    date: Date,
    summary: String,
}

fn read(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(|e| Error::Msg(format!("{}: {e}", path.display())))
}

fn write(path: &Path, text: &str) -> Result {
    std::fs::write(path, text).map_err(|e| Error::Msg(format!("{}: {e}", path.display())))
}

fn releases(text: &str) -> Result<Vec<Release>> {
    let table: toml::Table = text
        .parse()
        .map_err(|e| Error::Msg(format!("{RELEASES}: {e}")))?;
    let list = table
        .get("release")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| Error::Msg(format!("{RELEASES}: no [[release]] entries")))?;
    list.iter()
        .map(|entry| {
            let field = |key: &str| {
                entry.get(key).and_then(toml::Value::as_str).ok_or_else(|| {
                    Error::Msg(format!("{RELEASES}: a release has no string `{key}`"))
                })
            };
            Ok(Release {
                version: Version::parse(field("version")?)?,
                date: Date::parse(field("date")?)?,
                summary: field("summary")?.to_owned(),
            })
        })
        .collect()
}

/// The `version = "..."` line of `[workspace.package]`: (byte range of the value, value).
fn workspace_version(manifest: &str) -> Result<(std::ops::Range<usize>, String)> {
    let mut in_package = false;
    let mut offset = 0;
    for line in manifest.split_inclusive('\n') {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_package = trimmed == "[workspace.package]";
        } else if in_package {
            if let Some(rest) = trimmed.strip_prefix("version") {
                let value = rest.trim_start().strip_prefix('=').map(str::trim);
                if let Some(v) = value.and_then(|v| v.strip_prefix('"')?.strip_suffix('"')) {
                    let start = offset + line.find('"').unwrap_or(0) + 1;
                    return Ok((start..start + v.len(), v.to_owned()));
                }
            }
        }
        offset += line.len();
    }
    Err(Error::Msg(
        "Cargo.toml: no `version = \"...\"` in [workspace.package]".into(),
    ))
}

fn current_version(root: &Path) -> Result<String> {
    workspace_version(&read(&root.join("Cargo.toml"))?).map(|(_, v)| v)
}

// ------------------------------------------------------------------------------- rendering

fn environment() -> Result<minijinja::Environment<'static>> {
    let syntax = minijinja::syntax::SyntaxConfig::builder()
        .trim_blocks(true)
        .keep_trailing_newline(true)
        .build()
        .map_err(|e| Error::Msg(format!("template syntax: {e}")))?;
    let mut env = minijinja::Environment::new();
    env.set_syntax(syntax);
    env.set_undefined_behavior(minijinja::UndefinedBehavior::Strict);
    Ok(env)
}

fn context(current: &Version, releases: &[Release]) -> minijinja::Value {
    let history: Vec<BTreeMap<&str, String>> = releases
        .iter()
        .map(|r| {
            BTreeMap::from([
                ("version", r.version.upstream()),
                ("deb_version", r.version.tilde()),
                ("rpm_version", r.version.tilde()),
                ("date", r.date.iso()),
                ("deb_date", r.date.debian()),
                ("rpm_date", r.date.rpm()),
                ("summary", r.summary.clone()),
            ])
        })
        .collect();
    minijinja::context! {
        version => current.upstream(),
        rpm_version => current.tilde(),
        deb_version => current.tilde(),
        pkgver => current.pkgver(),
        prerelease => current.pre.is_some(),
        releases => minijinja::Value::from(history),
    }
}

fn render(
    env: &minijinja::Environment<'_>,
    template: &Path,
    ctx: &minijinja::Value,
) -> Result<String> {
    let source = read(template)?;
    env.render_str(&source, ctx)
        .map_err(|e| Error::Msg(format!("{}: {e:#}", template.display())))
}

/// Every `<path>.j2` under `packaging/templates`, with the file it renders to.
fn templates(root: &Path) -> Result<Vec<(PathBuf, PathBuf)>> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result {
        let entries =
            std::fs::read_dir(dir).map_err(|e| Error::Msg(format!("{}: {e}", dir.display())))?;
        for entry in entries {
            let path = entry
                .map_err(|e| Error::Msg(format!("{}: {e}", dir.display())))?
                .path();
            if path.is_dir() {
                walk(&path, out)?;
            } else if path.extension().is_some_and(|e| e == "j2") {
                out.push(path);
            }
        }
        Ok(())
    }
    let base = root.join(TEMPLATES);
    let mut found = Vec::new();
    walk(&base, &mut found)?;
    found.sort();
    found
        .into_iter()
        .map(|template| {
            let relative = template
                .strip_prefix(&base)
                .map_err(|_| Error::Msg(format!("{} outside {TEMPLATES}", template.display())))?
                .with_extension("");
            Ok((template.clone(), root.join("packaging").join(relative)))
        })
        .collect()
}

/// Rendered contents of every generated file, after checking the two sources agree.
fn rendered(root: &Path) -> Result<Vec<(PathBuf, String)>> {
    let current = Version::parse(&current_version(root)?)?;
    let history = releases(&read(&root.join(RELEASES))?)?;
    match history.first() {
        Some(latest) if latest.version == current => {}
        Some(latest) => {
            return Err(Error::Msg(format!(
                "Cargo.toml is at {} but the newest entry of {RELEASES} is {}: bump with \
                 `cargo xtask version <new> --summary ...`",
                current.upstream(),
                latest.version.upstream()
            )))
        }
        None => return Err(Error::Msg(format!("{RELEASES}: no releases"))),
    }
    let env = environment()?;
    let ctx = context(&current, &history);
    templates(root)?
        .into_iter()
        .map(|(template, output)| Ok((output, render(&env, &template, &ctx)?)))
        .collect()
}

fn display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn check(root: &Path) -> Result {
    let mut stale = Vec::new();
    for (path, text) in rendered(root)? {
        if std::fs::read_to_string(&path).ok().as_deref() != Some(text.as_str()) {
            stale.push(display(root, &path));
        }
    }
    if stale.is_empty() {
        println!("packaging files match {RELEASES} and their templates");
        Ok(())
    } else {
        Err(Error::Msg(format!(
            "out of date: {}. Edit packaging/templates/ or {RELEASES}, not the generated \
             files, then run `cargo xtask version --render`",
            stale.join(", ")
        )))
    }
}

fn write_rendered(root: &Path) -> Result {
    for (path, text) in rendered(root)? {
        write(&path, &text)?;
        println!("rendered {}", display(root, &path));
    }
    Ok(())
}

/// A TOML basic string for `text`.
fn toml_string(text: &str) -> String {
    toml::Value::String(text.to_owned()).to_string()
}

fn bump(root: &Path, new: &str, summary: &str, date: Option<String>) -> Result {
    let version = Version::parse(new)?;
    let date = match date {
        Some(d) => Date::parse(&d)?,
        None => Date::today(),
    };
    let manifest_path = root.join("Cargo.toml");
    let manifest = read(&manifest_path)?;
    let (range, current) = workspace_version(&manifest)?;
    let releases_path = root.join(RELEASES);
    let releases_text = read(&releases_path)?;
    if releases(&releases_text)?
        .iter()
        .any(|r| r.version == version)
    {
        return Err(Error::Msg(format!("{new} is already in {RELEASES}")));
    }

    // Sources: the version in Cargo.toml and a new newest entry in releases.toml.
    let mut manifest = manifest;
    manifest.replace_range(range, &version.upstream());
    write(&manifest_path, &manifest)?;
    let entry = format!(
        "[[release]]\nversion = {}\ndate = {}\nsummary = {}\n\n",
        toml_string(&version.upstream()),
        toml_string(&date.iso()),
        toml_string(summary)
    );
    let at = releases_text
        .find("[[release]]")
        .unwrap_or(releases_text.len());
    let mut releases_text = releases_text;
    releases_text.insert_str(at, &entry);
    write(&releases_path, &releases_text)?;

    // Lockfiles only change the workspace crates' own versions: no network needed.
    exec(cargo().args(["update", "--workspace", "--offline"]))?;
    let mut fuzz = cargo();
    fuzz.args(["update", "--offline", "--manifest-path", "fuzz/Cargo.toml"]);
    for krate in FUZZ_DEPS {
        fuzz.args(["-p", krate]);
    }
    exec(&mut fuzz)?;

    write_rendered(root)?;

    let notes = root.join(format!(".github/release-notes/v{}.md", version.upstream()));
    if !notes.exists() {
        let ctx = context(&version, &releases(&releases_text)?);
        let text = render(&environment()?, &root.join(RELEASE_NOTES_TEMPLATE), &ctx)?;
        write(&notes, &text)?;
        println!("wrote {} (fill in the TODOs)", display(root, &notes));
    }
    println!("{current} -> {}", version.upstream());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(args: &[&str]) -> Vec<String> {
        args.iter().map(|a| (*a).to_owned()).collect()
    }

    #[test]
    fn package_version_spellings() {
        let beta = Version::parse("0.1.0-beta.3").unwrap();
        assert_eq!(beta.upstream(), "0.1.0-beta.3");
        assert_eq!(beta.tilde(), "0.1.0~beta.3");
        assert_eq!(beta.pkgver(), "0.1.0beta3");
        let final_release = Version::parse("1.2.10").unwrap();
        assert_eq!(final_release.tilde(), "1.2.10");
        assert_eq!(final_release.pkgver(), "1.2.10");
        for bad in [
            "1.2",
            "1.2.3-",
            "1.2.x",
            "1.2.3-beta..1",
            "v1.2.3",
            "1.2.3-be_ta",
        ] {
            assert!(Version::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn changelog_dates() {
        let d = Date::parse("2026-11-04").unwrap();
        assert_eq!(d.debian(), "Wed, 04 Nov 2026 00:00:00 +0000");
        assert_eq!(d.rpm(), "Wed Nov 04 2026");
        assert_eq!(Date::parse("2026-10-03").unwrap().rpm(), "Sat Oct 03 2026");
        assert_eq!(Date::parse("2024-02-29").unwrap().weekday(), "Thu");
        assert_eq!(Date::from_days(0).iso(), "1970-01-01");
        for bad in ["2026-02-30", "2026-13-01", "26-11-04", "2026-11-4"] {
            assert!(Date::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn finds_the_workspace_version() {
        let manifest = "[workspace]\nversion = \"9\"\n\n[workspace.package]\nversion = \"0.1.0-beta.3\"\nedition = \"2021\"\n";
        let (range, v) = workspace_version(manifest).unwrap();
        assert_eq!(v, "0.1.0-beta.3");
        assert_eq!(&manifest[range], "0.1.0-beta.3");
    }

    #[test]
    fn arguments() {
        assert_eq!(parse(&[]).unwrap(), Mode::Show);
        assert_eq!(parse(&s(&["--check"])).unwrap(), Mode::Check);
        assert_eq!(
            parse(&s(&["0.2.0", "--summary", "x", "--date", "2026-12-01"])).unwrap(),
            Mode::Bump {
                version: "0.2.0".into(),
                summary: "x".into(),
                date: Some("2026-12-01".into()),
            }
        );
        assert!(parse(&s(&["0.2.0"])).is_err(), "summary required");
        assert!(parse(&s(&["--summary", "x"])).is_err());
        assert!(parse(&s(&["0.2.0", "--check"])).is_err());
        assert_eq!(parse(&s(&["--render"])).unwrap(), Mode::Render);
        assert!(parse(&s(&["--render", "--check"])).is_err());
    }

    #[test]
    fn checked_in_files_match_their_templates() {
        check(&workspace_root()).unwrap();
    }
}
