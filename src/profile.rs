//! Configuration profiles: `key = value` files under
//! `$XDG_CONFIG_HOME/packetread/profiles/` (default `~/.config`).
use std::{fmt::Write as _, fs, path::PathBuf};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Profile {
    pub theme: Option<String>,
    pub filter: Option<String>,
    pub memory: Option<u32>,
    pub max_packets: Option<u32>,
    pub table_percent: Option<u16>,
    pub details_percent: Option<u16>,
    pub keylog: Option<PathBuf>,
    /// Coloring rules: (color, display filter); the first match colors a row.
    pub colors: Vec<(String, String)>,
    /// Extra packet-list columns: (title, named field such as `http.host`).
    pub columns: Vec<(String, String)>,
    /// Saved filter buttons: (label, display filter).
    pub buttons: Vec<(String, String)>,
    /// Shift applied to displayed clock times, in milliseconds.
    pub time_shift_ms: Option<i64>,
}

pub const COLORS: [&str; 6] = ["red", "green", "yellow", "cyan", "purple", "muted"];

impl Profile {
    /// Names are restricted so a profile can never address another directory.
    pub fn path(name: &str) -> Result<PathBuf, String> {
        let valid = (1..=64).contains(&name.len())
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !valid {
            return Err("Profile names use 1–64 letters, digits, - and _".into());
        }
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
            // Windows has neither variable by default.
            .or_else(|| std::env::var_os("APPDATA").map(PathBuf::from))
            .ok_or("Cannot locate the configuration directory (set HOME)")?;
        Ok(base
            .join("packetread/profiles")
            .join(format!("{name}.conf")))
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let mut profile = Self::default();
        for (number, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let error = |message: &str| format!("profile line {}: {message}", number + 1);
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| error("expected key = value"))?;
            let value = value.trim();
            let number = |low: u32, high: u32| {
                value
                    .parse::<u32>()
                    .ok()
                    .filter(|n| (low..=high).contains(n))
                    .ok_or_else(|| error(&format!("{} must be {low}–{high}", key.trim())))
            };
            match key.trim() {
                "theme" if ["vivid", "indexed", "contrast"].contains(&value) => {
                    profile.theme = Some(value.into())
                }
                "theme" => return Err(error("theme must be vivid, indexed or contrast")),
                "filter" => {
                    crate::filter::Filter::parse(value).map_err(|e| error(&e))?;
                    profile.filter = Some(value.into());
                }
                "memory" => profile.memory = Some(number(1, 4096)?),
                "max_packets" => profile.max_packets = Some(number(1, 1_000_000)?),
                "table_percent" => profile.table_percent = Some(number(25, 75)? as u16),
                "details_percent" => profile.details_percent = Some(number(25, 70)? as u16),
                "keylog" => profile.keylog = Some(value.into()),
                "time_shift" => {
                    let seconds = value
                        .parse::<f64>()
                        .ok()
                        .filter(|seconds| seconds.abs() <= 315_360_000.0)
                        .ok_or_else(|| error("time_shift is a number of seconds"))?;
                    profile.time_shift_ms = Some((seconds * 1000.0) as i64);
                }
                key @ ("color" | "column" | "button") => {
                    // NAME VALUE: a color, column title or button label, then
                    // a display filter or field.
                    let (name, rest) = value
                        .split_once(char::is_whitespace)
                        .map(|(name, rest)| (name, rest.trim()))
                        .filter(|(name, rest)| {
                            (1..=12).contains(&name.len())
                                && name
                                    .bytes()
                                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                                && !rest.is_empty()
                        })
                        .ok_or_else(|| error(&format!("{key} needs a short name and a value")))?;
                    let (list, limit) = match key {
                        "color" => {
                            if !COLORS.contains(&name) {
                                return Err(error(
                                    "color must be red, green, yellow, cyan, purple or muted",
                                ));
                            }
                            crate::filter::Filter::parse(rest).map_err(|e| error(&e))?;
                            (&mut profile.colors, 32)
                        }
                        "column" => {
                            crate::filter::Field::parse(rest).map_err(|e| error(&e))?;
                            (&mut profile.columns, 4)
                        }
                        _ => {
                            crate::filter::Filter::parse(rest).map_err(|e| error(&e))?;
                            (&mut profile.buttons, 8)
                        }
                    };
                    if list.len() == limit {
                        return Err(error(&format!("at most {limit} {key} lines")));
                    }
                    list.push((name.into(), rest.into()));
                }
                _ => return Err(error("unknown key")),
            }
        }
        Ok(profile)
    }

    /// A missing profile is an error, except for the implicit `default`.
    pub fn load(name: &str) -> Result<Self, String> {
        let path = Self::path(name)?;
        match fs::read_to_string(&path) {
            Ok(text) => Self::parse(&text).map_err(|error| format!("{}: {error}", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && name == "default" => {
                Ok(Self::default())
            }
            Err(error) => Err(format!("{}: {error}", path.display())),
        }
    }

    fn to_text(&self) -> String {
        let mut text = String::from("# Packetread profile\n");
        let mut put = |key: &str, value: Option<String>| {
            if let Some(value) = value.filter(|v| !v.contains(['\n', '\r'])) {
                let _ = writeln!(text, "{key} = {value}");
            }
        };
        put("theme", self.theme.clone());
        put(
            "filter",
            self.filter.clone().filter(|f| !f.trim().is_empty()),
        );
        put("memory", self.memory.map(|n| n.to_string()));
        put("max_packets", self.max_packets.map(|n| n.to_string()));
        put("table_percent", self.table_percent.map(|n| n.to_string()));
        put(
            "details_percent",
            self.details_percent.map(|n| n.to_string()),
        );
        put(
            "keylog",
            self.keylog.as_ref().map(|p| p.display().to_string()),
        );
        put(
            "time_shift",
            self.time_shift_ms
                .map(|ms| (ms as f64 / 1000.0).to_string()),
        );
        for (key, list) in [
            ("color", &self.colors),
            ("column", &self.columns),
            ("button", &self.buttons),
        ] {
            for (name, value) in list {
                put(key, Some(format!("{name} {value}")));
            }
        }
        text
    }

    pub fn save(&self, name: &str) -> Result<PathBuf, String> {
        let path = Self::path(name)?;
        let write = |path: &PathBuf| {
            fs::create_dir_all(path.parent().unwrap_or(path))?;
            fs::write(path, self.to_text())
        };
        write(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_validates_and_round_trips() {
        let profile = Profile::parse(
            "# mine\ntheme = contrast\nfilter = proto=tcp port=443\nmemory = 64\nmax_packets=5000\n\
             table_percent = 40\ndetails_percent = 50\nkeylog = /tmp/keys.log\n",
        )
        .unwrap();
        assert_eq!(profile.theme.as_deref(), Some("contrast"));
        assert_eq!(profile.filter.as_deref(), Some("proto=tcp port=443"));
        assert_eq!(
            (profile.memory, profile.max_packets),
            (Some(64), Some(5000))
        );
        for (bad, expected) in [
            ("theme = neon", "line 1"),
            ("memory = 0", "1–4096"),
            ("filter = port=99999", "Port"),
            ("volume = 11", "unknown key"),
            ("nonsense", "key = value"),
        ] {
            assert!(Profile::parse(bad).unwrap_err().contains(expected), "{bad}");
        }
        let text =
            "color = red tcp.analysis=any\ncolor = green proto=dns\ncolumn = Host http.host\n\
                    button = Web proto=http or proto=tls\ntime_shift = -3600.5\n";
        let shown = Profile::parse(text).unwrap();
        assert_eq!(shown.colors[1], ("green".into(), "proto=dns".into()));
        assert_eq!(shown.columns, [("Host".into(), "http.host".into())]);
        assert_eq!(shown.buttons[0].1, "proto=http or proto=tls");
        assert_eq!(shown.time_shift_ms, Some(-3_600_500));
        assert_eq!(Profile::parse(&shown.to_text()).unwrap(), shown);
        for bad in [
            "color = pink proto=dns",
            "color = red",
            "color = red port=99999",
            "column = Host nosuch.field",
            "column = a-very-long-title http.host",
            "button = bad/label proto=dns",
            "time_shift = soon",
            &"column = H http.host\n".repeat(5),
        ] {
            assert!(Profile::parse(bad).is_err(), "{bad}");
        }
        for bad in ["", "../etc", "a/b", "x y", &"n".repeat(65)] {
            assert!(Profile::path(bad).is_err(), "{bad:?}");
        }
    }
}
