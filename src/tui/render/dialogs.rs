use super::{bold, button, input, panel};
use crate::{
    decode::safe_text,
    tui::app::{Action, App, Dialog, View, HELP},
};
use ratatui::{
    layout::Rect,
    style::Style,
    text::Line,
    widgets::{Clear, Paragraph, Wrap},
    Frame,
};

pub fn draw(frame: &mut Frame, app: &mut App) {
    let Some(dialog) = app.dialog.clone() else {
        return;
    };
    // A modal owns mouse hit regions: clicks must never reach controls behind it.
    app.regions.buttons.clear();
    let full = frame.area();
    let theme = app.theme;
    let text = matches!(dialog, Dialog::Text { .. });
    let width = full
        .width
        .saturating_sub(6)
        .min(if text { 140 } else { 84 });
    let height = match dialog {
        Dialog::Help => 19,
        Dialog::Text { .. } => full.height,
        Dialog::Interfaces { .. } => 16,
        _ => 8,
    }
    .min(full.height.saturating_sub(2));
    let area = Rect::new(
        full.x + (full.width - width) / 2,
        full.y + (full.height - height) / 2,
        width,
        height,
    );
    frame.render_widget(Clear, area);
    let title = match &dialog {
        Dialog::Help => " HELP ".into(),
        Dialog::Open(_) => " OPEN CAPTURE FILE ".into(),
        Dialog::Bpf(_) => " CAPTURE FILTER (BPF) ".into(),
        Dialog::Export(_, false) => " SAVE DISPLAYED PACKETS ".into(),
        Dialog::Export(_, true) => " SAVE SELECTED PACKET ".into(),
        Dialog::Find(_) => " FIND IN PACKET BYTES ".into(),
        Dialog::Comment(_) => " PACKET COMMENT ".into(),
        Dialog::Goto(_) => " GO TO PACKET ".into(),
        Dialog::KeyLog(_) => " TLS KEY LOG ".into(),
        Dialog::Interfaces { .. } => " SELECT INTERFACES ".into(),
        Dialog::Text { title, .. } => safe_text(title),
    };
    let inner = panel(frame, area, title, theme.cyan, theme);
    let content = Rect::new(
        inner.x + 1,
        inner.y,
        inner.width.saturating_sub(2),
        inner.height.saturating_sub(2),
    );
    match &dialog {
        Dialog::Help => {
            let text = if app.ingest.status.permission_denied {
                let helper = crate::source::helper_path()
                    .map(|path| format!("'{}'", path.display().to_string().replace('\'', "'\\''")))
                    .unwrap_or_else(|_| "<path-to-packetread-capture>".into());
                format!(
                    "Live capture permission is missing.\n\n\
                    Linux requires CAP_NET_RAW to open a packet socket. Only the\n\
                    capture helper needs it; grant it in another terminal:\n\n\
                    sudo setcap cap_net_raw=ep {helper}\n\n\
                    Then click Start again; no restart is needed.\n\
                    Reapply the capability after rebuilding or upgrading.\n\n\
                    Opening saved capture files needs no extra permission."
                )
            } else {
                HELP.join("\n")
            };
            frame.render_widget(
                Paragraph::new(safe_text_multiline(&text))
                    .style(Style::default().fg(theme.text))
                    .wrap(Wrap { trim: false }),
                content,
            );
        }
        Dialog::Text {
            lines,
            offset,
            view,
            ..
        } => {
            let rows = content.height as usize;
            let offset = (*offset).min(lines.len().saturating_sub(rows));
            let visible: Vec<_> = lines
                .iter()
                .skip(offset)
                .take(rows)
                .map(|line| Line::raw(safe_text(line)))
                .collect();
            frame.render_widget(
                Paragraph::new(visible).style(Style::default().fg(theme.text)),
                content,
            );
            let options: &[(&str, Action)] = match view {
                View::Stats => &[
                    ("Unit (u)", Action::ViewUnit),
                    ("Interval - ", Action::ViewInterval(false)),
                    ("Interval + ", Action::ViewInterval(true)),
                ],
                View::Follow => &[
                    ("Hex (h)", Action::ViewHex),
                    ("Decrypt (d)", Action::ViewDecrypt),
                ],
                View::Help => &[],
            };
            let mut x = inner.x + 1;
            let y = inner.bottom().saturating_sub(1);
            for (label, action) in [
                ("Up", Action::ScrollText(-10)),
                ("Down", Action::ScrollText(10)),
            ]
            .iter()
            .chain(options)
            {
                let width = label.len() as u16 + 4;
                if x + width + 13 > inner.right() {
                    break;
                }
                button(
                    frame,
                    app,
                    Rect::new(x, y, width, 1),
                    label,
                    action.clone(),
                    true,
                );
                x += width + 1;
            }
        }
        Dialog::Open(text)
        | Dialog::Bpf(text)
        | Dialog::Export(text, _)
        | Dialog::Find(text)
        | Dialog::Comment(text)
        | Dialog::Goto(text)
        | Dialog::KeyLog(text) => {
            let hint = match dialog {
                Dialog::Open(_) => "Enter a PCAP/PCAPNG path. Opening begins a new session.",
                Dialog::Bpf(_) => "Example: tcp port 443 · applies when you click Start again.",
                Dialog::Export(..) => {
                    "New file path; the extension picks the format:\n.pcap .pcapng (raw bytes) · .json .csv (decoded)"
                }
                Dialog::Find(_) => "Text (case-insensitive), or hex:de:ad:be:ef for bytes.",
                Dialog::Comment(_) => "Comment for the selected packet. Empty removes it.",
                Dialog::Goto(_) => "Packet number. A file reloads its window there if needed.",
                _ => "Path of an SSLKEYLOGFILE key log. Empty unloads it.",
            };
            frame.render_widget(
                Paragraph::new(hint).style(Style::default().fg(theme.muted)),
                content,
            );
            input(
                frame,
                Rect::new(content.x, content.y + 2, content.width, 1),
                text,
                true,
                theme,
            );
        }
        Dialog::Interfaces {
            entries,
            selected,
            checked,
        } => {
            if entries.is_empty() {
                frame.render_widget(
                    Paragraph::new("No capture interfaces found.")
                        .style(Style::default().fg(theme.yellow)),
                    content,
                );
            }
            let offset = selected.saturating_sub(content.height.saturating_sub(1) as usize);
            for (index, entry) in entries
                .iter()
                .enumerate()
                .skip(offset)
                .take(content.height as usize)
            {
                let rect = Rect::new(
                    content.x,
                    content.y + (index - offset) as u16,
                    content.width,
                    1,
                );
                let style = if index == *selected {
                    bold(theme.bg).bg(theme.cyan)
                } else {
                    Style::default().fg(theme.text)
                };
                frame.render_widget(
                    Paragraph::new(Line::styled(
                        format!(
                            " [{}] {}",
                            if checked.contains(&index) { 'x' } else { ' ' },
                            safe_text(entry)
                        ),
                        style,
                    )),
                    rect,
                );
                app.regions
                    .buttons
                    .push((rect, Action::SelectInterface(index)));
            }
        }
    }
    let y = inner.bottom().saturating_sub(1);
    if !matches!(dialog, Dialog::Help | Dialog::Text { .. }) {
        button(
            frame,
            app,
            Rect::new(inner.x + 1, y, 12, 1),
            "Apply",
            Action::ApplyDialog,
            true,
        );
    }
    button(
        frame,
        app,
        Rect::new(inner.right().saturating_sub(12), y, 12, 1),
        "Close",
        Action::CloseDialog,
        true,
    );
}

fn safe_text_multiline(text: &str) -> String {
    text.lines().map(safe_text).collect::<Vec<_>>().join("\n")
}
