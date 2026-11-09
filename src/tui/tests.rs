use super::{
    app::{Action, App, Dialog, Pane, TextInput},
    input, render,
};
use crate::decode::Packet;
use crossterm::event::{Event, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::{backend::TestBackend, Terminal};

fn app() -> App {
    let mut app = App::new(None, 1024 * 1024, 100, "vivid");
    for id in 1..=30 {
        app.session
            .insert(Packet::new(id, 0, 64, 999, vec![0; 64].into_boxed_slice()));
    }
    app.session.follow = false;
    app.session.select_index(0);
    app.tick();
    app
}

fn draw(app: &mut App, width: u16, height: u16) -> Terminal<TestBackend> {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|f| render::draw(f, app)).unwrap();
    terminal
}

fn mouse(app: &mut App, kind: MouseEventKind, x: u16, y: u16) {
    input::handle(
        app,
        Event::Mouse(MouseEvent {
            kind,
            column: x,
            row: y,
            modifiers: KeyModifiers::NONE,
        }),
    );
}

#[test]
fn renders_all_panes_and_themes_without_overflow() {
    let mut app = app();
    for theme in ["vivid", "indexed", "contrast"] {
        app.theme = super::theme::Theme::named(theme);
        let terminal = draw(&mut app, 140, 42);
        let text: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect();
        for expected in [
            "PACKETREAD",
            "PROTOCOL DETAILS",
            "HEX / ASCII",
            "DISPLAY FILTER",
        ] {
            assert!(text.contains(expected), "missing {expected}");
        }
        for (width, height) in [(80, 24), (60, 22), (20, 5), (1, 1)] {
            let _ = draw(&mut app, width, height);
        }
    }
}

#[test]
fn mouse_selects_rows_scrolls_and_drags_dividers() {
    let mut app = app();
    let _ = draw(&mut app, 140, 42);
    let rows = app.regions.packets;
    mouse(
        &mut app,
        MouseEventKind::Down(MouseButton::Left),
        rows.x + 3,
        rows.y + 2,
    );
    assert_eq!(app.session.selected, Some(3));
    mouse(&mut app, MouseEventKind::ScrollDown, rows.x + 3, rows.y);
    assert_eq!(app.packet_offset, 3);
    let divider = app.regions.horizontal;
    let body = app.regions.body;
    mouse(
        &mut app,
        MouseEventKind::Down(MouseButton::Left),
        divider.x,
        divider.y,
    );
    mouse(
        &mut app,
        MouseEventKind::Drag(MouseButton::Left),
        divider.x,
        body.y + body.height / 3,
    );
    assert!(app.table_percent < 55);
    mouse(
        &mut app,
        MouseEventKind::Up(MouseButton::Left),
        divider.x,
        divider.y,
    );
    let _ = draw(&mut app, 80, 24);
    assert_eq!(app.regions.horizontal.height, 0);
}

#[test]
fn modal_blocks_clicks_on_underlying_controls() {
    let mut app = app();
    app.dialog = Some(Dialog::Help);
    let _ = draw(&mut app, 140, 42);
    mouse(&mut app, MouseEventKind::Down(MouseButton::Left), 1, 1);
    assert!(matches!(app.dialog, Some(Dialog::Help)));
    assert!(!app.quit);
}

#[test]
fn mouse_can_reach_filter_and_narrow_tabs() {
    let mut app = app();
    let _ = draw(&mut app, 80, 24);
    let filter = app
        .regions
        .buttons
        .iter()
        .find(|(_, a)| matches!(a, Action::Filter))
        .unwrap()
        .0;
    mouse(
        &mut app,
        MouseEventKind::Down(MouseButton::Left),
        filter.x,
        filter.y,
    );
    assert!(app.editing_filter);
    app.filter = TextInput::new("proto=unknown".into());
    let apply = app
        .regions
        .buttons
        .iter()
        .find(|(_, a)| matches!(a, Action::ApplyFilter))
        .unwrap()
        .0;
    mouse(
        &mut app,
        MouseEventKind::Down(MouseButton::Left),
        apply.x,
        apply.y,
    );
    assert!(!app.editing_filter);
    let tab = app
        .regions
        .buttons
        .iter()
        .find(|(_, a)| matches!(a, Action::Focus(Pane::Details)))
        .unwrap()
        .0;
    mouse(
        &mut app,
        MouseEventKind::Down(MouseButton::Left),
        tab.x,
        tab.y,
    );
    assert_eq!(app.pane, Pane::Details);
}

#[test]
fn unicode_input_preserves_character_boundaries() {
    let mut input = TextInput::new("aé🦀".into());
    input.left();
    input.backspace();
    assert_eq!(input.value, "a🦀");
    input.delete();
    assert_eq!(input.value, "a");
    input.insert("\x1b[31m");
    assert!(!input.value.contains('\x1b'));
}

#[test]
fn capture_permission_help_shows_the_capability_fix() {
    let mut app = app();
    app.source = Some(crate::source::SourceSpec::Live {
        interface: "lo".into(),
        filter: String::new(),
        snaplen: 65535,
        promiscuous: false,
    });
    app.status.error = Some(
        "libpcap error: Attempt to create packet socket failed - CAP_NET_RAW may be required"
            .into(),
    );
    app.tick();
    app.apply(Action::Help);
    let terminal = draw(&mut app, 140, 42);
    let text: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|c| c.symbol())
        .collect();
    assert!(text.contains("sudo setcap cap_net_raw=ep"));
    assert!(text.contains("Restart the application"));
}

#[test]
fn advancing_offline_windows_does_not_skip_packets() {
    use crate::source::SourceSpec;
    use std::time::{Duration, Instant};
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/demo.pcap");
    let mut app = App::new(Some(SourceSpec::File(path)), 1024 * 1024, 3, "vivid");
    app.start();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut ids = Vec::new();
    loop {
        assert!(Instant::now() < deadline, "offline loading stalled");
        app.tick();
        if app.window_full {
            assert!(app.session.len() <= 3);
            ids.extend(app.session.visible.iter().copied());
            app.apply(Action::NextWindow);
        } else if app.status.done {
            ids.extend(app.session.visible.iter().copied());
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(ids, (1..=11).collect::<Vec<_>>());
}
