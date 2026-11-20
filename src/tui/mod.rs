mod app;
mod dashboard;
mod input;
mod render;
mod theme;

use crate::source::SourceSpec;
use app::App;
use crossterm::{
    cursor::Show,
    event::{
        self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::{
    io,
    path::PathBuf,
    time::{Duration, Instant},
};

struct TerminalGuard;

fn restore() {
    let _ = disable_raw_mode();
    let _ = execute!(
        io::stdout(),
        DisableMouseCapture,
        DisableBracketedPaste,
        LeaveAlternateScreen,
        Show
    );
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore();
    }
}

pub struct Options {
    pub source: Option<SourceSpec>,
    pub memory: usize,
    pub max_packets: usize,
    pub theme: String,
    /// Display filter applied at startup.
    pub filter: String,
    pub table_percent: Option<u16>,
    pub details_percent: Option<u16>,
    pub keylog: Option<PathBuf>,
    /// Profile that `P` saves to.
    pub profile: String,
    /// Coloring rules, custom columns and saved filters, as in a profile.
    pub colors: Vec<(String, String)>,
    pub columns: Vec<(String, String)>,
    pub buttons: Vec<(String, String)>,
    pub time_shift_ms: i64,
}

pub fn run(options: Options) -> io::Result<()> {
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore();
        previous_hook(info);
    }));
    let _guard = TerminalGuard;
    enable_raw_mode()?;
    execute!(
        io::stdout(),
        EnterAlternateScreen,
        EnableMouseCapture,
        EnableBracketedPaste
    )?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    terminal.clear()?;
    let mut app = App::new(
        options.source,
        options.memory,
        options.max_packets,
        &options.theme,
    );
    app.profile = options.profile;
    app.set_presentation(options.colors, options.columns, options.buttons);
    app.time_shift_ns = i128::from(options.time_shift_ms) * 1_000_000;
    app.table_percent = options.table_percent.unwrap_or(app.table_percent);
    app.details_percent = options.details_percent.unwrap_or(app.details_percent);
    if !options.filter.is_empty() {
        app.filter = app::TextInput::new(options.filter);
        app.apply(app::Action::ApplyFilter);
    }
    if app.source.is_some() {
        app.start();
    }
    if let Some(path) = options.keylog {
        app.load_keylog(path);
    }
    let interval = Duration::from_millis(33);
    let mut dirty = true;
    while !app.quit {
        let start = Instant::now();
        dirty |= app.tick();
        if dirty {
            terminal.draw(|frame| render::draw(frame, &mut app))?;
            dirty = false;
        }
        // Keep packet ingestion and rendering progressing even during an input flood.
        for _ in 0..64 {
            let wait = interval.saturating_sub(start.elapsed());
            if !event::poll(wait)? {
                break;
            }
            input::handle(&mut app, event::read()?);
            dirty = true;
            if app.quit || start.elapsed() >= interval {
                break;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
