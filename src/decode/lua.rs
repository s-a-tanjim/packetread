//! Lua decoders: scripts that describe a protocol in code.
//!
//! ```lua
//! name = "Telemetry"
//! transport = "udp"        -- or "tcp"; leave out for both
//! ports = { 9999 }         -- leave out to see every undecoded payload
//! function decode(payload, src_port, dst_port)
//!   if #payload < 4 then return nil end
//!   return {
//!     info = "version " .. payload:byte(1),
//!     fields = { { label = "Version: " .. payload:byte(1), offset = 0, length = 1 } },
//!   }
//! end
//! ```
//!
//! A script is code the user chooses to run. It gets the string, table and
//! math libraries only: no files, processes, modules or output. Memory and
//! the instructions of each call are bounded, so a runaway script yields no
//! decode instead of hanging the program.
use super::extension::{Decoded, Extension, Transport};
use mlua::{Function, HookTriggers, Lua, LuaOptions, StdLib, Table, Value, VmState};
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc, Mutex,
};

const MEMORY_LIMIT: usize = 16 * 1024 * 1024;
/// The hook runs every `STEP` instructions; a call may take `MAX_STEPS` of them.
const STEP: u32 = 1000;
const MAX_STEPS: u32 = 2000;

pub struct LuaDecoder {
    name: String,
    transport: Option<Transport>,
    ports: Vec<u16>,
    lua: Mutex<Lua>,
    steps: Arc<AtomicU32>,
}

impl LuaDecoder {
    pub fn parse(source: &str) -> Result<Self, String> {
        let error = |error: mlua::Error| {
            let text = error.to_string();
            format!("Lua decoder: {}", text.lines().next().unwrap_or_default())
        };
        let lua = Lua::new_with(
            StdLib::STRING | StdLib::TABLE | StdLib::MATH,
            LuaOptions::default(),
        )
        .map_err(error)?;
        lua.set_memory_limit(MEMORY_LIMIT).map_err(error)?;
        let steps = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&steps);
        lua.set_hook(
            HookTriggers::new().every_nth_instruction(STEP),
            move |_, _| {
                if counter.fetch_add(1, Ordering::Relaxed) >= MAX_STEPS {
                    Err(mlua::Error::RuntimeError(
                        "the script exceeded its instruction budget".into(),
                    ))
                } else {
                    Ok(VmState::Continue)
                }
            },
        )
        .map_err(error)?;
        let globals = lua.globals();
        // The base library's ways to load code, read files or print.
        for name in [
            "dofile",
            "loadfile",
            "load",
            "loadstring",
            "require",
            "print",
            "collectgarbage",
        ] {
            globals.set(name, Value::Nil).map_err(error)?;
        }
        lua.load(source).set_name("decoder").exec().map_err(error)?;
        let name = globals
            .get::<Option<String>>("name")
            .map_err(error)?
            .filter(|name| {
                (1..=16).contains(&name.len())
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            })
            .ok_or("Lua decoder: set `name` to 1–16 letters, digits, - or _")?;
        let transport = match globals
            .get::<Option<String>>("transport")
            .map_err(error)?
            .as_deref()
        {
            Some("tcp") => Some(Transport::Tcp),
            Some("udp") => Some(Transport::Udp),
            None => None,
            Some(_) => return Err("Lua decoder: `transport` is \"tcp\" or \"udp\"".into()),
        };
        let ports = globals
            .get::<Option<Vec<u16>>>("ports")
            .map_err(|_| "Lua decoder: `ports` is a list of port numbers")?
            .unwrap_or_default();
        if ports.len() > 64 {
            return Err("Lua decoder: at most 64 ports".into());
        }
        globals
            .get::<Function>("decode")
            .map_err(|_| "Lua decoder: define function decode(payload, src_port, dst_port)")?;
        drop(globals);
        Ok(Self {
            name,
            transport,
            ports,
            lua: Mutex::new(lua),
            steps,
        })
    }
}

impl Extension for LuaDecoder {
    fn name(&self) -> &str {
        &self.name
    }

    fn decode(&self, transport: Transport, src: u16, dst: u16, payload: &[u8]) -> Option<Decoded> {
        if self.transport.is_some_and(|wanted| wanted != transport)
            || !(self.ports.is_empty() || self.ports.contains(&src) || self.ports.contains(&dst))
        {
            return None;
        }
        let lua = self.lua.lock().unwrap_or_else(|e| e.into_inner());
        self.steps.store(0, Ordering::Relaxed);
        let decode = lua.globals().get::<Function>("decode").ok()?;
        // Script errors, including an exhausted budget, mean "not decoded".
        let result = decode
            .call::<Value>((lua.create_string(payload).ok()?, src, dst))
            .ok()?;
        let Value::Table(table) = result else {
            return None;
        };
        let text = |table: &Table, key: &str| {
            let value = table.get::<Option<mlua::LuaString>>(key).ok()??;
            Some(
                value
                    .to_string_lossy()
                    .chars()
                    .take(200)
                    .collect::<String>(),
            )
        };
        let mut fields = Vec::new();
        if let Ok(Some(list)) = table.get::<Option<Table>>("fields") {
            for item in list.sequence_values::<Table>().take(64) {
                let item = item.ok()?;
                let number = |key: &str| {
                    let value = item.get::<Option<usize>>(key).ok().flatten();
                    value.unwrap_or(0).min(payload.len())
                };
                let (offset, length) = (number("offset"), number("length"));
                fields.push((
                    text(&item, "label").unwrap_or_default(),
                    offset..offset.saturating_add(length).min(payload.len()),
                ));
            }
        }
        Some(Decoded {
            info: text(&table, "info").unwrap_or_default(),
            fields,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCRIPT: &str = r#"
        name = "Telemetry"
        transport = "udp"
        ports = { 9999 }
        function decode(payload, src, dst)
          if #payload < 2 then return nil end
          if payload:byte(1) == 0xff then while true do end end
          if payload:byte(1) == 0xfe then return { info = string.rep("x", 1 << 30) } end
          if payload:byte(1) == 0xfd then return { info = 7, fields = { { offset = -1 }, 5 } } end
          return {
            info = "version " .. payload:byte(1) .. " to " .. dst,
            fields = { { label = "Version: " .. payload:byte(1), offset = 0, length = 1 },
                       { label = "Rest", offset = 1, length = 1000 } },
          }
        end
    "#;

    #[test]
    fn decodes_and_survives_runaway_or_malformed_scripts() {
        let decoder = LuaDecoder::parse(SCRIPT).unwrap();
        let decoded = decoder
            .decode(Transport::Udp, 5000, 9999, &[3, 1, 2])
            .unwrap();
        assert_eq!(decoded.info, "version 3 to 9999");
        assert_eq!(decoded.fields[0], ("Version: 3".to_string(), 0..1));
        // Ranges are clamped to the payload.
        assert_eq!(decoded.fields[1].1, 1..3);
        // Wrong transport or port, a short payload, an endless loop, a huge
        // allocation and wrongly typed results all decode to nothing.
        assert!(decoder
            .decode(Transport::Tcp, 5000, 9999, &[3, 1])
            .is_none());
        assert!(decoder
            .decode(Transport::Udp, 5000, 5001, &[3, 1])
            .is_none());
        assert!(decoder.decode(Transport::Udp, 9999, 1, &[3]).is_none());
        assert!(decoder
            .decode(Transport::Udp, 9999, 1, &[0xff, 0])
            .is_none());
        assert!(decoder
            .decode(Transport::Udp, 9999, 1, &[0xfe, 0])
            .is_none());
        assert!(decoder
            .decode(Transport::Udp, 9999, 1, &[0xfd, 0])
            .is_none());
        // The decoder still works afterwards.
        assert!(decoder.decode(Transport::Udp, 9999, 1, &[1, 0]).is_some());
    }

    #[test]
    fn the_sandbox_has_no_files_processes_modules_or_output() {
        let probe = |expression: &str| {
            let script = format!(
                "name = 'P'\nfunction decode(p) return {{ info = tostring({expression}) }} end"
            );
            let decoder = LuaDecoder::parse(&script).unwrap();
            decoder.decode(Transport::Tcp, 1, 2, b"x").unwrap().info
        };
        for global in [
            "os", "io", "require", "dofile", "loadfile", "load", "print", "debug", "package",
        ] {
            assert_eq!(probe(global), "nil", "{global}");
        }
        assert_eq!(probe("string.format('%d', 7)"), "7");
        for bad in [
            "function decode() end",
            "name = 'has space'\nfunction decode() end",
            "name = 'X'",
            "name = 'X'\ntransport = 'sctp'\nfunction decode() end",
            "name = 'X'\nports = 'all'\nfunction decode() end",
            "this is not lua",
            "name = 'X'\nfunction decode() end\nwhile true do end",
        ] {
            assert!(LuaDecoder::parse(bad).is_err(), "{bad}");
        }
    }
}
