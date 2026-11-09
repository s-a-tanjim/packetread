mod app;
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

pub fn run(
    source: Option<SourceSpec>,
    memory: usize,
    max_packets: usize,
    theme: &str,
) -> io::Result<()> {
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
    let mut app = App::new(source, memory, max_packets, theme);
    if app.source.is_some() {
        app.start();
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
