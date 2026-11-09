use super::{bold, button, input, panel};
use crate::{
    decode::safe_text,
    tui::app::{Action, App, Dialog},
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
    let width = full.width.saturating_sub(6).min(84);
    let height = match dialog {
        Dialog::Help => 19,
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
        Dialog::Help => " HELP ",
        Dialog::Open(_) => " OPEN CAPTURE FILE ",
        Dialog::Bpf(_) => " CAPTURE FILTER (BPF) ",
        Dialog::Interfaces { .. } => " SELECT INTERFACE ",
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
                let executable = std::env::current_exe()
                    .map(|path| format!("'{}'", path.display().to_string().replace('\'', "'\\''")))
                    .unwrap_or_else(|_| "<path-to-packetread>".into());
                format!(
                    "Live capture permission is missing.\n\n\
                    Linux requires CAP_NET_RAW to open a packet socket.\n\
                    Exit this application, then run in your terminal:\n\n\
                    sudo setcap cap_net_raw=ep {executable}\n\n\
                    Restart the application using that same binary.\n\
                    Reapply the capability after rebuilding the binary.\n\n\
                    Opening saved capture files needs no extra permission."
                )
            } else {
                [
                    "Mouse: click controls, packets, fields and tabs.",
                    "Wheel: scroll the pane under the pointer.",
                    "Drag pane dividers or scrollbars to resize / navigate.",
                    "Tab / 1 / 2 / 3: choose pane. Arrows / j k: move.",
                    "Enter / Left / Right: expand or collapse protocol layer.",
                    "Space: auto-scroll ON/OFF. s: stop. r: new session.",
                    "o: open file. i: interfaces. b: BPF for the next capture.",
                    "/: edit display filter. Enter or Apply: apply it.",
                    "Examples: proto=tcp port=443 · addr=192.0.2.1",
                    "Fields: proto, addr, src, dst, port. Space means AND.",
                    "n / Next: next bounded file window. Earlier data is evicted.",
                    "t: theme. q / Ctrl+C: quit. Esc: close dialog / editor.",
                    "BPF controls capture; display filters search retained packets.",
                    "OS drops may be unavailable. App drops and evictions differ.",
                    "TCP reassembly and decryption are not yet supported.",
                ]
                .join("\n")
            };
            frame.render_widget(
                Paragraph::new(safe_text_multiline(&text))
                    .style(Style::default().fg(theme.text))
                    .wrap(Wrap { trim: false }),
                content,
            );
        }
        Dialog::Open(text) | Dialog::Bpf(text) => {
            let hint = if matches!(dialog, Dialog::Open(_)) {
                "Enter a PCAP/PCAPNG path. Opening begins a new session."
            } else {
                "Example: tcp port 443 · applies when you click Start again."
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
        Dialog::Interfaces { entries, selected } => {
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
                    Paragraph::new(Line::styled(format!(" {}", safe_text(entry)), style)),
                    rect,
                );
                app.regions
                    .buttons
                    .push((rect, Action::SelectInterface(index)));
            }
        }
    }
    let y = inner.bottom().saturating_sub(1);
    if !matches!(dialog, Dialog::Help) {
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
