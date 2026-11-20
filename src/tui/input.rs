use super::app::{contains, Action, App, Dialog, Drag, Pane, Screen, TextInput, View};
use super::dashboard::{Command as DashboardCommand, Tab};
use crossterm::event::{
    Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};

pub fn handle(app: &mut App, event: Event) {
    match event {
        Event::Key(key) if key.kind != KeyEventKind::Release => key_event(app, key),
        Event::Mouse(mouse) => mouse_event(app, mouse),
        Event::Paste(text) => {
            if let Some(input) = active_input(app) {
                input.insert(&text);
            }
            if app.editing_filter {
                app.validate_filter();
            }
        }
        Event::Resize(_, _) => {
            app.drag = None;
            app.regions = Default::default();
        }
        _ => {}
    }
}

fn active_input(app: &mut App) -> Option<&mut TextInput> {
    match &mut app.dialog {
        Some(
            Dialog::Open(input)
            | Dialog::Bpf(input)
            | Dialog::Export(input, _)
            | Dialog::Find(input)
            | Dialog::Comment(input)
            | Dialog::Goto(input)
            | Dialog::KeyLog(input),
        ) => Some(input),
        None if app.editing_filter => Some(&mut app.filter),
        _ => None,
    }
}

fn key_event(app: &mut App, key: KeyEvent) {
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        app.apply(Action::Quit);
        return;
    }
    if key.code == KeyCode::Esc {
        if app.dialog.is_none() && !app.editing_filter {
            app.apply(Action::Screen(Screen::Packets));
        }
        app.apply(Action::CloseDialog);
        app.editing_filter = false;
        app.drag = None;
        return;
    }
    if active_input(app).is_some() {
        if key.code == KeyCode::Enter {
            app.apply(if app.dialog.is_some() {
                Action::ApplyDialog
            } else {
                Action::ApplyFilter
            });
            return;
        }
        if key.code == KeyCode::Tab && app.editing_filter && app.dialog.is_none() {
            app.complete_filter();
            return;
        }
        if let Some(input) = active_input(app) {
            match key.code {
                KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    *input = TextInput::default()
                }
                KeyCode::Char(c)
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    input.insert(&c.to_string())
                }
                KeyCode::Left => input.left(),
                KeyCode::Right => input.right(),
                KeyCode::Home => input.cursor = 0,
                KeyCode::End => input.cursor = input.value.len(),
                KeyCode::Backspace => input.backspace(),
                KeyCode::Delete => input.delete(),
                _ => {}
            }
        }
        if app.editing_filter {
            app.validate_filter();
        }
        return;
    }
    if app.dialog.is_some() {
        if key.code == KeyCode::Enter {
            app.apply(Action::ApplyDialog);
            return;
        }
        match &mut app.dialog {
            Some(Dialog::Interfaces {
                entries,
                selected,
                checked,
            }) => match key.code {
                KeyCode::Down | KeyCode::Char('j') => {
                    *selected = (*selected + 1).min(entries.len().saturating_sub(1))
                }
                KeyCode::Up | KeyCode::Char('k') => *selected = selected.saturating_sub(1),
                KeyCode::Char(' ') if !checked.remove(selected) => {
                    checked.insert(*selected);
                }
                _ => {}
            },
            Some(Dialog::Text { view, .. }) => {
                let action = match (key.code, *view) {
                    (KeyCode::Down | KeyCode::Char('j'), _) => Action::ScrollText(1),
                    (KeyCode::Up | KeyCode::Char('k'), _) => Action::ScrollText(-1),
                    (KeyCode::PageDown | KeyCode::Char(' '), _) => Action::ScrollText(20),
                    (KeyCode::PageUp, _) => Action::ScrollText(-20),
                    (KeyCode::Home | KeyCode::Char('g'), _) => Action::ScrollText(isize::MIN / 2),
                    (KeyCode::End | KeyCode::Char('G'), _) => Action::ScrollText(isize::MAX / 2),
                    (KeyCode::Char('q'), _) => Action::CloseDialog,
                    (KeyCode::Backspace | KeyCode::Char('S'), View::Stats) => Action::CloseDialog,
                    (KeyCode::Char('u'), View::Stats) => Action::ViewUnit,
                    (KeyCode::Char('+' | '='), View::Stats) => Action::ViewInterval(true),
                    (KeyCode::Char('-'), View::Stats) => Action::ViewInterval(false),
                    (KeyCode::Char('h'), View::Follow) => Action::ViewHex,
                    (KeyCode::Char('d'), View::Follow) => Action::ViewDecrypt,
                    _ => return,
                };
                app.apply(action);
            }
            _ => {}
        }
        return;
    }
    if app.screen == Screen::Stats {
        let command = match key.code {
            KeyCode::Enter | KeyCode::Right => DashboardCommand::Activate,
            KeyCode::Down | KeyCode::Char('j') => DashboardCommand::Move(1),
            KeyCode::Up | KeyCode::Char('k') => DashboardCommand::Move(-1),
            KeyCode::PageDown => DashboardCommand::Page(1),
            KeyCode::PageUp => DashboardCommand::Page(-1),
            KeyCode::Home | KeyCode::Char('g') => DashboardCommand::Move(isize::MIN),
            KeyCode::End | KeyCode::Char('G') => DashboardCommand::Move(isize::MAX),
            KeyCode::Backspace | KeyCode::Left => DashboardCommand::Back,
            KeyCode::Tab => DashboardCommand::NextTab(true),
            KeyCode::BackTab => DashboardCommand::NextTab(false),
            KeyCode::Char(digit @ '1'..='5') => {
                DashboardCommand::Tab(Tab::ALL[digit as usize - '1' as usize])
            }
            KeyCode::Char('r') => DashboardCommand::Refresh,
            KeyCode::Char('f') => DashboardCommand::Report,
            KeyCode::Char('u') => DashboardCommand::Unit,
            KeyCode::Char('d') => DashboardCommand::Direction,
            KeyCode::Char('p') => DashboardCommand::Packets,
            KeyCode::Char('x') => DashboardCommand::Unscope,
            // Keys that act on the capture or the whole interface still work.
            KeyCode::Char(
                'q' | '?' | 'o' | 'i' | 's' | 't' | '/' | 'w' | 'S' | 'E' | 'P' | 'b',
            )
            | KeyCode::F(_) => return global_key(app, key.code),
            _ => return,
        };
        app.apply(Action::Dashboard(command));
        return;
    }
    global_key(app, key.code);
}

fn global_key(app: &mut App, code: KeyCode) {
    let action = match code {
        KeyCode::Char('q') => Action::Quit,
        KeyCode::Char('?') | KeyCode::F(1) => Action::Help,
        KeyCode::Char('o') => Action::Open,
        KeyCode::Char('i') => Action::Interfaces,
        KeyCode::Char('s') => Action::Stop,
        KeyCode::Char('r') => Action::Start,
        KeyCode::Char(' ') => Action::Follow,
        KeyCode::Char('n') => Action::NextWindow,
        KeyCode::Char('p') => Action::PrevWindow,
        KeyCode::Char('w') => Action::Export(false),
        KeyCode::Char('W') => Action::Export(true),
        KeyCode::Char('f') => Action::Find,
        KeyCode::F(3) | KeyCode::Char('.') => Action::FindNext(true),
        KeyCode::Char(',') => Action::FindNext(false),
        KeyCode::Char('m') => Action::Mark,
        KeyCode::Char('c') => Action::Comment,
        KeyCode::Char(':') => Action::Goto,
        KeyCode::Char('S') => Action::Stats,
        KeyCode::Char('F') => Action::FollowStream,
        KeyCode::Char('K') => Action::KeyLog,
        KeyCode::Char('P') => Action::SaveProfile,
        KeyCode::Char('T') => Action::TimeFormat,
        KeyCode::Char('N') => Action::Resolve,
        KeyCode::Char('a') => Action::ApplyAsFilter,
        KeyCode::Char('E') => Action::Expert,
        KeyCode::Char('R') => Action::TimeReference,
        KeyCode::Char('Y') => Action::Graph,
        KeyCode::Char('D') => Action::FlowDiagram,
        KeyCode::Char('V') => Action::Voip,
        KeyCode::F(number @ 5..=12) => Action::SavedFilter(usize::from(number - 5)),
        KeyCode::Char('t') => Action::Theme,
        KeyCode::Char('b') => Action::Bpf,
        KeyCode::Char('/') => Action::Filter,
        KeyCode::Down | KeyCode::Char('j') => Action::Move(1),
        KeyCode::Up | KeyCode::Char('k') => Action::Move(-1),
        KeyCode::PageDown => Action::Move(10),
        KeyCode::PageUp => Action::Move(-10),
        KeyCode::Home | KeyCode::Char('g') => Action::Home,
        KeyCode::End | KeyCode::Char('G') => Action::End,
        KeyCode::Enter | KeyCode::Left | KeyCode::Right if app.pane == Pane::Details => {
            Action::Toggle
        }
        KeyCode::Tab => Action::Focus(match app.pane {
            Pane::Packets => Pane::Details,
            Pane::Details => Pane::Bytes,
            Pane::Bytes => Pane::Packets,
        }),
        KeyCode::Char('1') => Action::Focus(Pane::Packets),
        KeyCode::Char('2') => Action::Focus(Pane::Details),
        KeyCode::Char('3') => Action::Focus(Pane::Bytes),
        _ => return,
    };
    app.apply(action);
}

fn mouse_event(app: &mut App, mouse: MouseEvent) {
    let (x, y) = (mouse.column, mouse.row);
    match mouse.kind {
        MouseEventKind::Up(MouseButton::Left) => app.drag = None,
        MouseEventKind::Drag(MouseButton::Left) if app.dialog.is_none() => {
            if let Some(drag) = app.drag {
                drag_to(app, drag, x, y);
            }
        }
        MouseEventKind::Down(MouseButton::Left) => {
            if let Some(action) = app.regions.hit(x, y) {
                app.apply(action);
                return;
            }
            if app.dialog.is_some() {
                return;
            }
            app.editing_filter = false;
            if contains(app.regions.horizontal, x, y) {
                app.drag = Some(Drag::Horizontal);
                return;
            }
            if contains(app.regions.vertical, x, y) {
                app.drag = Some(Drag::Vertical);
                return;
            }
            if let Some(&(_, pane)) = app
                .regions
                .scrollbars
                .iter()
                .find(|(r, _)| contains(*r, x, y))
            {
                app.drag = Some(Drag::Scroll(pane));
                drag_to(app, Drag::Scroll(pane), x, y);
                return;
            }
            if contains(app.regions.packets, x, y) {
                app.apply(Action::SelectPacket(
                    app.packet_offset + (y - app.regions.packets.y) as usize,
                ));
            } else if contains(app.regions.details, x, y) {
                app.apply(Action::SelectDetail(
                    app.detail_offset + (y - app.regions.details.y) as usize,
                ));
            } else if contains(app.regions.bytes, x, y) {
                app.pane = Pane::Bytes;
            }
        }
        MouseEventKind::ScrollDown | MouseEventKind::ScrollUp => {
            let delta = if mouse.kind == MouseEventKind::ScrollDown {
                3
            } else {
                -3
            };
            if let Some(Dialog::Interfaces {
                entries, selected, ..
            }) = &mut app.dialog
            {
                *selected = selected
                    .saturating_add_signed(delta)
                    .min(entries.len().saturating_sub(1));
                return;
            }
            if matches!(app.dialog, Some(Dialog::Text { .. })) {
                app.apply(Action::ScrollText(delta));
                return;
            }
            if app.dialog.is_some() {
                return;
            }
            if app.screen == Screen::Stats {
                if contains(app.regions.body, x, y) {
                    app.apply(Action::Dashboard(DashboardCommand::Move(delta)));
                }
                return;
            }
            let pane = if contains(app.regions.packets, x, y) {
                Pane::Packets
            } else if contains(app.regions.details, x, y) {
                Pane::Details
            } else if contains(app.regions.bytes, x, y) {
                Pane::Bytes
            } else {
                return;
            };
            app.apply(Action::Scroll(pane, delta));
        }
        _ => {}
    }
}

fn drag_to(app: &mut App, drag: Drag, x: u16, y: u16) {
    match drag {
        Drag::Horizontal => {
            app.table_percent = ((u32::from(y.saturating_sub(app.regions.body.y)) * 100
                / u32::from(app.regions.body.height.max(1)))
                as u16)
                .clamp(25, 75);
        }
        Drag::Vertical => {
            app.details_percent = ((u32::from(x.saturating_sub(app.regions.body.x)) * 100
                / u32::from(app.regions.body.width.max(1)))
                as u16)
                .clamp(25, 70);
        }
        Drag::Scroll(pane) => {
            if let Some((rect, _)) = app.regions.scrollbars.iter().find(|(_, p)| *p == pane) {
                let offset =
                    usize::from(y.saturating_sub(rect.y).min(rect.height.saturating_sub(1)))
                        * app.max_offset(pane)
                        / usize::from(rect.height.saturating_sub(1).max(1));
                app.set_offset(pane, offset);
            }
        }
    }
}
