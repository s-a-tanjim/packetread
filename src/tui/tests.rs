use super::{
    app::{Action, App, Dialog, Pane, Screen, TextInput},
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
    key(&mut app, KeyCode::Char('f'));
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
    // The report closes onto the Stats screen; S returns to the packets.
    key(&mut app, KeyCode::Esc);
    assert_eq!(app.screen, Screen::Stats);
    key(&mut app, KeyCode::Char('S'));
    assert_eq!(app.screen, Screen::Packets);

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

fn dashboard(app: &App) -> &super::dashboard::Dashboard {
    assert_eq!(app.screen, Screen::Stats, "{}", app.notice);
    app.stats.as_deref().expect("Stats snapshot")
}

fn row(app: &App, target: super::dashboard::Target) -> usize {
    dashboard(app)
        .rows
        .iter()
        .position(|row| row.target == target)
        .unwrap_or_else(|| panic!("no row for {target:?}"))
}

fn click(app: &mut App, wanted: impl Fn(&Action) -> bool) {
    let rect = app
        .regions
        .buttons
        .iter()
        .find(|(_, action)| wanted(action))
        .expect("clickable region")
        .0;
    mouse(app, MouseEventKind::Down(MouseButton::Left), rect.x, rect.y);
}

fn screen_text(app: &mut App, width: u16, height: u16) -> String {
    let terminal = draw(app, width, height);
    let buffer = terminal.backend().buffer();
    buffer.content.iter().map(|cell| cell.symbol()).collect()
}

#[test]
fn stats_drills_into_filtered_stream_and_restores_snapshot() {
    use super::dashboard::{Command, Tab, Target};
    let mut app = loaded("protocols.pcap", 1000);
    filter(&mut app, "proto=http or proto=dns");
    let expected_count = app.session.visible().len();
    key(&mut app, KeyCode::Char('S'));
    let ip = "192.0.2.10".parse().unwrap();
    assert_eq!(dashboard(&app).stats.total.packets, expected_count as u64);
    let index = row(&app, Target::Ip(ip));
    for (width, height) in [(140, 42), (60, 22)] {
        let _ = draw(&mut app, width, height);
        click(
            &mut app,
            |a| matches!(a, Action::Dashboard(Command::Open(i)) if *i == index),
        );
        assert_eq!(dashboard(&app).tab, Tab::Conversations);
        assert_eq!(dashboard(&app).address, Some(ip));
        key(&mut app, KeyCode::Backspace);
        assert_eq!(dashboard(&app).tab, Tab::Overview);
        assert_eq!(dashboard(&app).selected, index);
    }
    key(&mut app, KeyCode::Enter);
    let stream = row(&app, Target::Stream(0));
    app.apply(Action::Dashboard(Command::Move(stream as isize)));
    key(&mut app, KeyCode::Enter);
    settle(&mut app);
    assert_eq!(app.screen, Screen::Packets);
    assert_eq!(app.session.visible().len(), 2);
    assert!(app
        .session
        .visible_packets()
        .all(|p| p.summary.stream == Some(0)));
    // The list opens on the row's first packet, not on an earlier selection.
    assert_eq!(app.session.selected_index(), Some(0));
    assert_eq!(app.packet_offset, 0);
    key(&mut app, KeyCode::Char('S'));
    assert!(!app.notice.contains("returns to Stats"));
    assert_eq!(dashboard(&app).selected, stream);
    settle(&mut app);
    assert_eq!(app.session.visible().len(), expected_count);
    // The address heading the tab has packets outside its streams too.
    key(&mut app, KeyCode::Char('p'));
    settle(&mut app);
    assert!(app.filter.value.contains("addr=192.0.2.10 and id<="));
    key(&mut app, KeyCode::Char('S'));
    key(&mut app, KeyCode::Char('x'));
    assert_eq!(dashboard(&app).address, None);
    key(&mut app, KeyCode::Backspace);
    assert_eq!(dashboard(&app).tab, Tab::Overview);
}

#[test]
fn long_rankings_name_what_they_leave_out_and_wide_graphs_their_interval() {
    use super::dashboard::Tab;
    use std::net::IpAddr;
    let mut app = loaded("demo.pcap", 1000);
    key(&mut app, KeyCode::Char('S'));
    let mut stats = crate::stats::Stats::new(1.0);
    for host in 0..120u8 {
        let wire_len = if host == 0 { 1_000_000 } else { 100 };
        let seconds = i128::from(host) * 1_000_000_000;
        let mut packet = Packet::new(
            u64::from(host) + 1,
            seconds,
            wire_len,
            999,
            vec![0; 16].into(),
        );
        packet.summary.src = Some(IpAddr::from([10, 0, 0, host]));
        packet.summary.dst = Some(IpAddr::from([172, 16, 0, 1]));
        stats.add(&packet);
    }
    let replaced = app.stats.as_mut().unwrap();
    replaced.stats = stats;
    replaced.show(Tab::Ips);
    let text = screen_text(&mut app, 140, 42);
    assert!(text.contains("IPs · 1 / 50 · top 50 of 121"), "{text}");
    // A share too small for one decimal is not shown as zero.
    assert!(text.contains("<0.1%"));
    // The selection follows its address when a new ranking moves the row.
    key(&mut app, KeyCode::Down);
    let second = dashboard(&app).rows[1].target;
    key(&mut app, KeyCode::Char('d'));
    assert_eq!(dashboard(&app).selected, 0);
    assert_eq!(dashboard(&app).rows[0].target, second);
    key(&mut app, KeyCode::Char('1'));
    // 120 one-second intervals share 66 columns, so each column covers two.
    let text = screen_text(&mut app, 140, 42);
    assert!(text.contains("Traffic · bytes per 2 s"), "{text}");
    assert!(text.contains("in 2 s"));
}

#[test]
fn zero_window_opens_the_advertised_window_field_and_handles_eviction() {
    use super::dashboard::{Command, Target};
    use crate::decode::diag;
    let mut app = loaded("protocols.pcap", 30);
    key(&mut app, KeyCode::Char('S'));
    let zero_window = diag::NAMES
        .iter()
        .position(|(bit, _)| *bit == diag::ZERO_WINDOW)
        .unwrap();
    let event = row(&app, Target::Issue(zero_window));
    app.apply(Action::Dashboard(Command::Open(event)));
    assert_eq!(app.screen, Screen::Packets);
    assert_eq!(app.session.selected(), Some(12));
    assert_eq!(app.pane, Pane::Details);
    let (layer, field) = app.detail_rows()[app.detail_selected];
    assert_eq!(app.layers[layer].fields[field.unwrap()].label, "Window: 0");
    key(&mut app, KeyCode::Char('S'));
    assert_eq!(dashboard(&app).selected, event);
    for id in 30..65 {
        app.session
            .insert(Packet::new(id, 0, 7, 999, vec![0; 7].into()));
    }
    // Stats recount arrivals without a key press, at most once a second.
    app.tick();
    assert!(dashboard(&app).stats.total.bytes > 7 * 30);
    app.apply(Action::Dashboard(Command::Open(event)));
    assert!(dashboard(&app).message.contains("Packet #12"));
    app.stats_next = std::time::Instant::now();
    app.tick();
    assert_eq!(dashboard(&app).stats.total.bytes, 7 * 30);
    assert_eq!(
        dashboard(&app).message,
        "Matching packets have no decoded IP addresses"
    );
}

#[test]
fn ip_rows_show_demo_shares_and_directional_rank() {
    use super::dashboard::{Command, Tab};
    let mut app = loaded("demo.pcap", 1000);
    key(&mut app, KeyCode::Char('S'));
    key(&mut app, KeyCode::Char('2'));
    assert_eq!(dashboard(&app).tab, Tab::Ips);
    assert_eq!(
        dashboard(&app).rows[0].cells[..4],
        ["1", "192.0.2.10", "497 B", "44.1%"]
    );
    let text = screen_text(&mut app, 140, 42);
    assert!(text.contains("Rank: [Bytes] Packets (u)"), "{text}");
    assert!(text.contains("44.1%  ██"), "{text}");
    click(&mut app, |a| {
        matches!(a, Action::Dashboard(Command::Direction))
    });
    key(&mut app, KeyCode::Char('d'));
    assert_eq!(dashboard(&app).rows[0].cells[1], "198.51.100.8");
    assert_eq!(dashboard(&app).rows[0].cells[2], "426 B");
    key(&mut app, KeyCode::Char('u'));
    assert_eq!(dashboard(&app).rows[0].cells[2], "8 pkts");
    // A filter applied on the Stats screen takes a new snapshot there.
    filter(&mut app, "id=999");
    assert_eq!(dashboard(&app).tab, Tab::Ips);
    assert_eq!(dashboard(&app).message, "No packets match");
}

#[test]
fn stats_tabs_switch_scroll_and_list_packets_for_protocols_and_issues() {
    use super::dashboard::{Command, Tab, Target};
    let mut app = loaded("protocols.pcap", 1000);
    let all = app.session.visible().len();
    let _ = draw(&mut app, 140, 42);
    click(&mut app, |a| matches!(a, Action::Screen(Screen::Stats)));
    for (width, height) in [(140, 42), (100, 30), (80, 24), (60, 22)] {
        for tab in Tab::ALL {
            app.apply(Action::Dashboard(Command::Tab(tab)));
            let text = screen_text(&mut app, width, height);
            assert!(text.contains("Stats · file window"), "{text}");
            // The toolbar button now leads back to the packets.
            assert!(text.contains("[ Inspect ]") && !text.contains("[ Stats ]"));
            assert!(!dashboard(&app).rows.is_empty(), "{tab:?} has no rows");
        }
    }
    let wide = {
        key(&mut app, KeyCode::Char('1'));
        screen_text(&mut app, 140, 42)
    };
    for panel in ["Traffic", "Top talkers", "Protocols", "TCP issues"] {
        assert!(wide.contains(panel), "missing {panel}");
    }

    click(&mut app, |a| {
        matches!(a, Action::Dashboard(Command::Tab(Tab::Protocols)))
    });
    assert_eq!(dashboard(&app).tab, Tab::Protocols);
    let _ = draw(&mut app, 60, 22);
    let body = app.regions.body;
    mouse(&mut app, MouseEventKind::ScrollDown, body.x + 2, body.y + 2);
    assert_eq!(dashboard(&app).selected, 3);
    key(&mut app, KeyCode::PageDown);
    key(&mut app, KeyCode::End);
    let _ = draw(&mut app, 60, 22);
    let d = dashboard(&app);
    assert_eq!(d.selected, d.rows.len() - 1);
    assert!(d.offset > 0 && d.offset + d.page_rows == d.rows.len());

    let dns = row(&app, Target::Protocol("DNS"));
    app.apply(Action::Dashboard(Command::Open(dns)));
    settle(&mut app);
    assert_eq!(app.screen, Screen::Packets);
    assert!(app.filter.value.starts_with("proto=dns and id<="));
    assert!(!app.session.visible().is_empty());
    assert!(app
        .session
        .visible_packets()
        .all(|p| p.summary.protocol.name() == "DNS"));
    key(&mut app, KeyCode::Char('S'));
    assert_eq!(dashboard(&app).selected, dns);
    settle(&mut app);
    assert_eq!(app.session.visible().len(), all);

    key(&mut app, KeyCode::Tab);
    assert_eq!(dashboard(&app).tab, Tab::Issues);
    key(&mut app, KeyCode::Char('p'));
    settle(&mut app);
    assert!(app.filter.value.starts_with("tcp.analysis="));
    assert!(app.session.visible_packets().all(|p| p.summary.diag != 0));
    key(&mut app, KeyCode::Char('S'));
    key(&mut app, KeyCode::BackTab);
    assert_eq!(dashboard(&app).tab, Tab::Protocols);
    key(&mut app, KeyCode::Esc);
    assert_eq!(app.screen, Screen::Packets);
    // Typing a filter by hand ends the drill-down: Stats starts afresh.
    filter(&mut app, "proto=dns");
    key(&mut app, KeyCode::Char('S'));
    assert_eq!(dashboard(&app).tab, Tab::Overview);
    assert_eq!(dashboard(&app).filter, "proto=dns");
}

#[test]
fn opening_stats_while_the_filter_updates_waits_for_it() {
    let mut app = loaded("protocols.pcap", 1000);
    app.filter = TextInput::new("proto=dns".into());
    app.apply(Action::ApplyFilter);
    key(&mut app, KeyCode::Char('S'));
    assert_eq!(app.screen, Screen::Stats);
    let _ = draw(&mut app, 80, 24);
    settle(&mut app);
    let d = dashboard(&app);
    assert_eq!(d.filter, "proto=dns");
    assert_eq!(d.stats.total.packets, app.session.visible().len() as u64);
    assert!(d.stats.total.packets > 0);
}
