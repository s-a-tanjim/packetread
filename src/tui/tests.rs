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
    app.source = Some(crate::source::SourceSpec::Live(crate::source::LiveSpec {
        interfaces: vec!["lo".into()],
        ..Default::default()
    }));
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
    assert!(text.contains("packetread-capture"));
    assert!(text.contains("click Start again"));
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

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Opens a fixture and ticks until `done` holds.
fn loaded(name: &str, max_packets: usize) -> App {
    let source = crate::source::SourceSpec::File(fixture(name));
    let mut app = App::new(Some(source), 1024 * 1024, max_packets, "vivid");
    app.start();
    settle(&mut app);
    app
}

fn settle(app: &mut App) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        app.tick();
        let idle = app.ingest.window_full || app.ingest.status.done;
        if idle && !app.searching() && !app.session.filtering() {
            return;
        }
        assert!(std::time::Instant::now() < deadline, "loading stalled");
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

fn key(app: &mut App, code: KeyCode) {
    input::handle(app, Event::Key(KeyEvent::new(code, KeyModifiers::NONE)));
}

fn type_and_apply(app: &mut App, text: &str) {
    text.chars().for_each(|c| key(app, KeyCode::Char(c)));
    key(app, KeyCode::Enter);
}

fn filter(app: &mut App, text: &str) {
    app.filter = TextInput::new(text.into());
    app.apply(Action::ApplyFilter);
    assert_eq!(app.filter_error, None);
    settle(app);
}

fn text_view(app: &App) -> String {
    match &app.dialog {
        Some(Dialog::Text { title, lines, .. }) => format!("{title}\n{}", lines.join("\n")),
        _ => panic!("no text view open: {}", app.notice),
    }
}

#[test]
fn marks_comments_search_and_export_work_from_the_keyboard() {
    let mut app = loaded("protocols.pcap", 1000);
    let _ = draw(&mut app, 140, 42);
    key(&mut app, KeyCode::Char('f'));
    type_and_apply(&mut app, "laptop");
    assert_eq!(app.session.selected(), Some(19));
    key(&mut app, KeyCode::Char('.'));
    assert_eq!(
        app.session.selected(),
        Some(19),
        "a lone match wraps to itself"
    );
    key(&mut app, KeyCode::Char('f'));
    type_and_apply(&mut app, "absent");
    assert_eq!(app.notice, "No match");
    key(&mut app, KeyCode::Char('f'));
    type_and_apply(&mut app, "hex:fe:53:4d:42");
    assert_eq!(app.session.selected(), Some(24));
    key(&mut app, KeyCode::Char('f'));
    type_and_apply(&mut app, "hex:zz");
    assert!(app.notice.contains("Invalid hex"));

    key(&mut app, KeyCode::Char('m'));
    key(&mut app, KeyCode::Char('c'));
    type_and_apply(&mut app, "negotiation \x1b starts");
    app.tick();
    assert_eq!(app.layers[0].label, "Comment: negotiation  starts");
    let screen: String = draw(&mut app, 140, 42)
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(screen.contains("*     24"));

    key(&mut app, KeyCode::Char('/'));
    type_and_apply(&mut app, "marked or proto=dhcp");
    settle(&mut app);
    assert_eq!(app.session.visible().len(), 2);
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("marked.pcapng");
    key(&mut app, KeyCode::Char('w'));
    type_and_apply(&mut app, path.to_str().unwrap());
    assert!(app.notice.starts_with("Saved 2 packets"), "{}", app.notice);
    let mut saved = crate::offline::OfflineCapture::open(&path).unwrap();
    let stop = std::sync::atomic::AtomicBool::new(false);
    assert!(saved.next_packet(&stop).unwrap().unwrap().comment.is_none());
    let second = saved.next_packet(&stop).unwrap().unwrap();
    assert_eq!(second.comment.as_deref(), Some("negotiation  starts"));
    // Saving never overwrites, and W saves only the selected packet.
    key(&mut app, KeyCode::Char('w'));
    type_and_apply(&mut app, path.to_str().unwrap());
    assert!(app.notice.starts_with("Export failed"), "{}", app.notice);
    let single = temp.path().join("one.csv");
    key(&mut app, KeyCode::Char('W'));
    type_and_apply(&mut app, single.to_str().unwrap());
    assert_eq!(std::fs::read_to_string(single).unwrap().lines().count(), 2);
}

#[test]
fn statistics_and_stream_views_open_scroll_and_reconfigure() {
    let mut app = loaded("protocols.pcap", 1000);
    app.apply(Action::Home);
    key(&mut app, KeyCode::Char('S'));
    assert!(text_view(&app).contains("CONVERSATIONS · top 15 of 9"));
    assert!(text_view(&app).contains("TRAFFIC · packets per 1 s"));
    key(&mut app, KeyCode::Char('u'));
    key(&mut app, KeyCode::Char('-'));
    assert!(text_view(&app).contains("TRAFFIC · bytes per 0.1 s"));
    for (width, height) in [(140, 42), (60, 22)] {
        let _ = draw(&mut app, width, height);
        let down = app
            .regions
            .buttons
            .iter()
            .find(|(_, action)| matches!(action, Action::ScrollText(10)))
            .unwrap()
            .0;
        mouse(
            &mut app,
            MouseEventKind::Down(MouseButton::Left),
            down.x,
            down.y,
        );
        mouse(&mut app, MouseEventKind::ScrollDown, 5, 5);
        assert!(matches!(app.dialog, Some(Dialog::Text { offset: 13, .. })));
        key(&mut app, KeyCode::Home);
    }
    key(&mut app, KeyCode::Esc);

    key(&mut app, KeyCode::Char('F'));
    let stream = text_view(&app);
    assert!(stream.contains("TCP stream 0: 192.0.2.10:40000 ↔ 198.51.100.8:80"));
    assert!(stream.contains("  hello world!"));
    key(&mut app, KeyCode::Char('h'));
    assert!(text_view(&app).contains("68 65 6c 6c 6f"));
    key(&mut app, KeyCode::Esc);
    // ARP has no stream to follow.
    app.session
        .insert(Packet::new(99, 0, 1, 999, vec![0].into()));
    app.apply(Action::End);
    key(&mut app, KeyCode::Char('F'));
    assert!(app.dialog.is_none() && app.notice.contains("Select a TCP or UDP packet"));
}

#[test]
fn key_log_decrypts_the_followed_tls_stream() {
    let mut app = loaded("tls.pcap", 1000);
    app.apply(Action::Home);
    key(&mut app, KeyCode::Char('F'));
    assert!(text_view(&app).contains("press K to load a key log"));
    assert!(!text_view(&app).contains("GET /secret"));
    key(&mut app, KeyCode::Esc);
    key(&mut app, KeyCode::Char('K'));
    type_and_apply(&mut app, fixture("tls.keys").to_str().unwrap());
    assert!(
        app.notice.starts_with("Loaded 6 TLS secrets"),
        "{}",
        app.notice
    );
    // The file is re-analyzed: decrypted messages appear in the packet list.
    settle(&mut app);
    let decrypted: Vec<_> = app
        .session
        .packets()
        .filter(|p| p.summary.info.starts_with("[Decrypted TLS]"))
        .map(|p| (p.summary.protocol, p.summary.info.clone()))
        .collect();
    assert_eq!(decrypted.len(), 6);
    assert_eq!(
        decrypted[0],
        (
            crate::decode::Protocol::Http,
            "[Decrypted TLS] GET /secret HTTP/1.1".into()
        )
    );
    assert_eq!(decrypted[1].1, "[Decrypted TLS] HTTP/1.1 200 OK");
    key(&mut app, KeyCode::Char('/'));
    type_and_apply(&mut app, "proto=http bytes contains \"decrypted body\"");
    settle(&mut app);
    assert_eq!(app.session.visible().len(), 3);
    app.apply(Action::Home);
    app.tick();
    assert!(app.layers.iter().any(|layer| layer.label == "HTTP"));
    key(&mut app, KeyCode::Char('F'));
    let plain = text_view(&app);
    assert!(plain.contains("[TLS decrypted with the key log]"));
    assert!(plain.contains("→ client (43 bytes) · HTTP: GET /secret HTTP/1.1"));
    key(&mut app, KeyCode::Char('d'));
    assert!(!text_view(&app).contains("GET /secret"));
}

#[test]
fn file_windows_can_be_revisited_and_searched_past_the_loaded_window() {
    let ids = |app: &App| app.session.visible().iter().copied().collect::<Vec<_>>();
    let mut app = loaded("demo.pcap", 3);
    assert_eq!(ids(&app), [1, 2, 3]);
    key(&mut app, KeyCode::Char('p'));
    assert_eq!(app.notice, "Already at the first file window");
    for expected in [[4, 5, 6], [7, 8, 9]] {
        key(&mut app, KeyCode::Char('n'));
        settle(&mut app);
        assert_eq!(ids(&app), expected);
    }
    for expected in [[4, 5, 6], [1, 2, 3]] {
        key(&mut app, KeyCode::Char('p'));
        settle(&mut app);
        assert_eq!(ids(&app), expected);
    }
    // Marks survive leaving and re-entering a window.
    app.apply(Action::Home);
    key(&mut app, KeyCode::Char('m'));
    key(&mut app, KeyCode::Char(':'));
    type_and_apply(&mut app, "10");
    settle(&mut app);
    assert_eq!(
        (ids(&app), app.session.selected()),
        (vec![10, 11], Some(10))
    );
    key(&mut app, KeyCode::Char('p'));
    settle(&mut app);
    assert!(app.session.packet(1).unwrap().mark);

    // "ping" is in packet 7, two windows ahead; a miss returns to this window.
    key(&mut app, KeyCode::Char('f'));
    type_and_apply(&mut app, "ping");
    settle(&mut app);
    assert_eq!(
        (ids(&app), app.session.selected()),
        (vec![7, 8, 9], Some(7))
    );
    key(&mut app, KeyCode::Char('.'));
    settle(&mut app);
    assert_eq!(app.notice, "No further match in the capture");
    assert_eq!(ids(&app), [7, 8, 9]);
    key(&mut app, KeyCode::Char(':'));
    type_and_apply(&mut app, "nope");
    assert!(app.notice.contains("not displayed"));
}

#[test]
fn interface_dialog_selects_several_interfaces() {
    let mut app = app();
    app.dialog = Some(Dialog::Interfaces {
        entries: vec!["eth0".into(), "wlan0".into(), "lo".into()],
        selected: 0,
        checked: Default::default(),
    });
    let _ = draw(&mut app, 140, 42);
    key(&mut app, KeyCode::Char(' '));
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Char(' '));
    key(&mut app, KeyCode::Enter);
    assert_eq!(app.source.as_ref().unwrap().label(), "eth0+lo");
    assert!(app.notice.contains("eth0 + lo"));
}

#[test]
fn selection_filters_time_formats_names_and_expert_view() {
    let screen = |app: &mut App| -> String {
        let terminal = draw(app, 150, 42);
        let cells = &terminal.backend().buffer().content;
        cells.iter().map(|cell| cell.symbol()).collect()
    };
    let mut app = loaded("protocols.pcap", 1000);
    app.apply(Action::Home);
    assert!(screen(&mut app).contains("22:13:20.000000"));
    key(&mut app, KeyCode::Char('T'));
    assert!(screen(&mut app).contains("SINCE FIRST"));
    key(&mut app, KeyCode::Char('T'));
    let delta = screen(&mut app);
    assert!(delta.contains("SINCE PREVIOUS") && delta.contains("0.010000"));
    key(&mut app, KeyCode::Char('T'));
    assert!(screen(&mut app).contains("2023-11-14 22:13:20"));

    // Names come only from DNS answers seen in the capture.
    assert!(!screen(&mut app).contains("example.com:53000"));
    filter(&mut app, "addr=192.0.2.7 or proto=dns");
    assert_eq!(
        app.session.name(&"192.0.2.7".parse().unwrap()),
        Some("example.com")
    );
    key(&mut app, KeyCode::Char('N'));
    assert!(app.resolve);

    // `a` on a packet filters its conversation; on a field, that field.
    filter(&mut app, "proto=http");
    app.apply(Action::Home);
    key(&mut app, KeyCode::Char('a'));
    settle(&mut app);
    assert_eq!(
        (app.filter.value.as_str(), app.session.visible().len()),
        ("stream=0", 12)
    );
    app.apply(Action::Home);
    app.tick();
    key(&mut app, KeyCode::Char('2'));
    let ttl = app
        .detail_rows()
        .iter()
        .position(|&(l, f)| f.is_some_and(|f| app.layers[l].fields[f].label == "TTL: 64"));
    app.detail_selected = ttl.unwrap();
    key(&mut app, KeyCode::Char('a'));
    settle(&mut app);
    assert_eq!(app.filter.value, "field contains \"TTL: 64\"");
    assert_eq!(app.session.visible().len(), 27);

    filter(&mut app, "");
    key(&mut app, KeyCode::Char('E'));
    let expert = text_view(&app);
    assert!(expert.contains("EXPERT INFORMATION"));
    assert!(expert.contains("1 × TCP retransmission · packets 11"));
    assert!(expert.contains("2 × IP datagram reassembled from fragments · packets 26, 28"));
    let _ = screen(&mut app);
}

#[test]
fn presentation_rules_columns_buttons_completion_and_analysis_views() {
    let screen = |app: &mut App| -> String {
        let terminal = draw(app, 170, 42);
        let cells = &terminal.backend().buffer().content;
        cells.iter().map(|cell| cell.symbol()).collect()
    };
    let mut app = loaded("protocols.pcap", 1000);
    app.set_presentation(
        vec![
            ("red".into(), "tcp.analysis=any".into()),
            ("green".into(), "proto=http".into()),
            ("pink".into(), "not a filter (".into()),
        ],
        vec![("Host".into(), "http.host".into())],
        vec![
            ("Web".into(), "proto=http".into()),
            ("DNS".into(), "proto=dns".into()),
        ],
    );
    // The rule that does not parse is dropped, the others keep their order.
    assert_eq!(app.colors.len(), 2);
    app.apply(Action::Home);
    let text = screen(&mut app);
    assert!(text.contains("HOST") && text.contains("example.com"));
    assert!(text.contains("[ Web ]") && text.contains("[ DNS ]"));
    // The HTTP request row (not selected) is drawn in the rule's color.
    let terminal = draw(&mut app, 170, 42);
    let buffer = terminal.backend().buffer();
    let green = app.theme.green;
    let colored = (0..buffer.area.height).any(|y| {
        let row: String = (0..buffer.area.width)
            .map(|x| buffer[(x, y)].symbol())
            .collect();
        let info = row.find("GET /index.html");
        info.is_some_and(|at| buffer[(row[..at].chars().count() as u16, y)].fg == green)
    });
    assert!(colored);

    // A saved filter by mouse and by function key.
    let web = app
        .regions
        .buttons
        .iter()
        .find(|(_, action)| matches!(action, Action::SavedFilter(0)))
        .unwrap()
        .0;
    mouse(
        &mut app,
        MouseEventKind::Down(MouseButton::Left),
        web.x + 1,
        web.y,
    );
    settle(&mut app);
    assert_eq!(app.filter.value, "proto=http");
    key(&mut app, KeyCode::F(6));
    settle(&mut app);
    assert_eq!(app.filter.value, "proto=dns");
    assert!(app.session.visible().len() > 1);

    // Tab completes a unique word and lists several candidates.
    app.apply(Action::Filter);
    app.filter = TextInput::new("http.h".into());
    key(&mut app, KeyCode::Tab);
    assert_eq!(app.filter.value, "http.host");
    app.filter = TextInput::new("proto=dns and tcp.a".into());
    key(&mut app, KeyCode::Tab);
    assert_eq!(app.filter.value, "proto=dns and tcp.a");
    assert!(app.notice.contains("tcp.ack") && app.notice.contains("tcp.analysis="));
    app.filter = TextInput::new("(proto=ht".into());
    key(&mut app, KeyCode::Tab);
    assert_eq!(app.filter.value, "(proto=http");
    app.filter = TextInput::new("zzz".into());
    key(&mut app, KeyCode::Tab);
    assert_eq!(app.notice, "No completion");
    key(&mut app, KeyCode::Esc);

    // A time reference re-bases relative times; the clock can be shifted.
    filter(&mut app, "");
    app.apply(Action::Home);
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Char('R'));
    assert_eq!(app.time_reference.map(|r| r.0), Some(2));
    let text = screen(&mut app);
    assert!(text.contains("SINCE REFERENCE") && text.contains("-0.010000"));
    key(&mut app, KeyCode::Char('R'));
    assert!(app.time_reference.is_none());
    app.time_format = super::app::TimeFormat::Clock;
    app.time_shift_ns = 3_600_000_000_000;
    assert!(screen(&mut app).contains("23:13:20.000000"));

    // Graphs, flow diagram and VoIP open as text views.
    let title = |app: &App| match &app.dialog {
        Some(Dialog::Text { title, lines, .. }) => (title.clone(), lines.join("\n")),
        _ => panic!("no text view"),
    };
    app.apply(Action::Home);
    key(&mut app, KeyCode::Char('Y'));
    let (name, graph) = title(&app);
    assert!(name.contains("STREAM GRAPHS"));
    assert!(graph.contains("Time-sequence · stream 0") && graph.contains("Throughput"));
    key(&mut app, KeyCode::Esc);
    key(&mut app, KeyCode::Char('D'));
    let (_, flow) = title(&app);
    assert!(flow.contains("192.0.2.10") && flow.contains('▶') && flow.contains("GET /index.html"));
    key(&mut app, KeyCode::Esc);
    key(&mut app, KeyCode::Char('V'));
    assert!(title(&app).1.contains("SIP calls: 0"));
}

#[test]
fn rate_charts_fill_their_panels_at_any_terminal_width() {
    for width in [100, 140, 320, 700] {
        let mut app = app();
        app.ingest.packet_history.iter_mut().for_each(|v| *v = 5);
        app.ingest.byte_history.iter_mut().for_each(|v| *v = 5);
        let terminal = draw(&mut app, width, 42);
        let buffer = terminal.backend().buffer();
        let symbol = |x: u16, y: u16| buffer.cell((x, y)).unwrap().symbol();
        let row = |y: u16| (0..width).map(|x| symbol(x, y)).collect::<String>();
        let title = (0..42).find(|&y| row(y).contains("pkt/s")).unwrap();
        let mut bars = 0;
        for x in 0..width - 1 {
            if symbol(x, title + 1) == "█" {
                bars += 1;
                assert_ne!(
                    symbol(x + 1, title + 1),
                    " ",
                    "gap after column {x} at width {width}"
                );
            }
        }
        assert!(bars > 0, "no chart drawn at width {width}");
    }
}
