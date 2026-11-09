use super::{
    app::{Action, App, Dialog, Pane, TextInput},
    input, render,
};
use crate::decode::Packet;
use crossterm::event::{
    Event, KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::{backend::TestBackend, Terminal};

fn app() -> App {
    let mut app = App::new(None, 1024 * 1024, 100, "vivid");
    for id in 1..=30 {
        app.session
            .insert(Packet::new(id, 0, 64, 999, vec![0; 64].into_boxed_slice()));
    }
    app.session.unfollow();
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
fn auto_scroll_defaults_on_and_can_pause_and_resume_as_packets_arrive() {
    for (width, height) in [(140, 42), (60, 22)] {
        let mut app = App::new(None, 1024 * 1024, 100, "vivid");
        let append = |app: &mut App, id| {
            app.session
                .insert(Packet::new(id, 0, 64, 999, vec![0; 64].into_boxed_slice()));
            app.tick();
        };
        for id in 1..=30 {
            append(&mut app, id);
        }
        let _ = draw(&mut app, width, height);
        assert!(app.session.follow());
        assert_eq!(app.session.selected(), Some(30));
        assert_eq!(app.packet_offset, app.max_offset(Pane::Packets));

        let toggle = app
            .regions
            .buttons
            .iter()
            .find(|(_, action)| matches!(action, Action::Follow))
            .unwrap()
            .0;
        mouse(
            &mut app,
            MouseEventKind::Down(MouseButton::Left),
            toggle.x,
            toggle.y,
        );
        let paused_offset = app.packet_offset;
        append(&mut app, 31);
        let _ = draw(&mut app, width, height);
        assert!(!app.session.follow());
        assert_eq!(app.session.len(), 31);
        assert_eq!(app.session.selected(), Some(30));
        assert_eq!(app.packet_offset, paused_offset);

        input::handle(
            &mut app,
            Event::Key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE)),
        );
        let _ = draw(&mut app, width, height);
        assert!(app.session.follow());
        assert_eq!(app.session.selected(), Some(31));
        assert_eq!(app.packet_offset, app.max_offset(Pane::Packets));
        append(&mut app, 32);
        let _ = draw(&mut app, width, height);
        assert_eq!(app.session.selected(), Some(32));
        assert_eq!(app.packet_offset, app.max_offset(Pane::Packets));

        let rows = app.regions.packets;
        mouse(&mut app, MouseEventKind::ScrollUp, rows.x, rows.y);
        assert!(!app.session.follow());
        let browsing_offset = app.packet_offset;
        append(&mut app, 33);
        let _ = draw(&mut app, width, height);
        assert_eq!(app.packet_offset, browsing_offset);
        assert_eq!(app.session.selected(), Some(32));
    }
}

#[test]
fn auto_scroll_state_and_toolbar_controls_remain_visible_on_narrow_terminals() {
    let mut app = App::new(None, 1024 * 1024, 100, "vivid");
    for expected in ["Auto-scroll ON", "Auto-scroll OFF"] {
        for width in 60..=140 {
            let terminal = draw(&mut app, width, 22);
            let text: String = terminal
                .backend()
                .buffer()
                .content
                .iter()
                .map(|cell| cell.symbol())
                .collect();
            assert!(
                text.contains(expected),
                "missing {expected} at width {width}"
            );
            assert!(app
                .regions
                .buttons
                .iter()
                .any(|(_, action)| matches!(action, Action::Quit)));
        }
        app.apply(Action::Follow);
    }
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
    assert_eq!(app.session.selected(), Some(3));
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
    app.ingest.status.error = Some(
        "libpcap error: Attempt to create packet socket failed - CAP_NET_RAW may be required"
            .into(),
    );
    app.ingest.status.permission_denied = true;
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
        if app.ingest.window_full {
            assert!(app.session.len() <= 3);
            ids.extend(app.session.visible().iter().copied());
            app.apply(Action::NextWindow);
        } else if app.ingest.status.done {
            ids.extend(app.session.visible().iter().copied());
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(ids, (1..=11).collect::<Vec<_>>());
}
