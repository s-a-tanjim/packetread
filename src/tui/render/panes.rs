use super::{bold, panel, scrollbar};
use crate::{
    decode::{safe_text, Summary},
    tui::app::{App, Pane},
};
use ratatui::{
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

pub fn packets(frame: &mut Frame, app: &mut App, area: Rect) {
    let theme = app.theme;
    let title = format!(
        " PACKETS · {} matches {} ",
        app.session.visible().len(),
        if app.session.follow() {
            "· AUTO-SCROLL ON"
        } else {
            "· AUTO-SCROLL OFF"
        }
    );
    let inner = panel(
        frame,
        area,
        title,
        if app.pane == Pane::Packets {
            theme.cyan
        } else {
            theme.muted
        },
        theme,
    );
    let rows = Rect::new(
        inner.x,
        inner.y.saturating_add(1),
        inner.width.saturating_sub(1),
        inner.height.saturating_sub(1),
    );
    app.regions.packets = rows;
    if app.session.follow() {
        app.reveal_packet();
    }
    app.packet_offset = app.packet_offset.min(app.max_offset(Pane::Packets));
    let wide = inner.width >= 100;
    let endpoint_width = if wide { 26 } else { 16 };
    let header = if wide {
        format!(
            "{:>7} {:>11} {:<26} {:<26} {:<7} {:>6}  INFO",
            "NO.", "TIME", "SOURCE", "DESTINATION", "PROTO", "LEN"
        )
    } else {
        format!(
            "{:>6} {:<16} {:<16} {:<6} {:>5}",
            "NO.", "SOURCE", "DESTINATION", "PROTO", "LEN"
        )
    };
    frame.render_widget(
        Paragraph::new(header).style(bold(theme.muted)),
        Rect::new(inner.x, inner.y, inner.width, inner.height.min(1)),
    );
    let mut lines = Vec::new();
    for id in app
        .session
        .visible()
        .iter()
        .skip(app.packet_offset)
        .take(rows.height as usize)
    {
        if let Some(packet) = app.session.packet(*id) {
            let summary = &packet.summary;
            let source = fit(&endpoint(summary, true), endpoint_width);
            let destination = fit(&endpoint(summary, false), endpoint_width);
            let time = packet.timestamp_ns.rem_euclid(86_400_000_000_000) as f64 / 1_000_000_000.0;
            let lead = if wide {
                format!("{:>7} {:>11.6} {source} {destination} ", id, time)
            } else {
                format!("{:>6} {source} {destination} ", id)
            };
            let mut spans = vec![
                Span::styled(lead, Style::default().fg(theme.text)),
                Span::styled(
                    format!("{:<7}", summary.protocol.name()),
                    bold(theme.protocol(summary.protocol)),
                ),
                Span::styled(
                    format!("{:>6} ", packet.wire_len),
                    Style::default().fg(theme.muted),
                ),
            ];
            if wide {
                spans.push(Span::styled(
                    if summary.warning.is_some() {
                        "! "
                    } else {
                        "  "
                    },
                    bold(theme.yellow),
                ));
                spans.push(Span::styled(
                    safe_text(&summary.info),
                    Style::default().fg(theme.text),
                ));
            }
            if app.session.selected() == Some(*id) {
                for span in &mut spans {
                    span.style = bold(theme.bg).bg(theme.cyan);
                }
            }
            lines.push(Line::from(spans));
        }
    }
    if app.session.visible().is_empty() {
        let text = if app.session.filtering() {
            "Rebuilding filter…"
        } else if !app.session.is_empty() {
            "No matching packets. Click the filter to change it."
        } else {
            "Open a PCAP file or choose an interface and click Start."
        };
        lines.push(Line::styled(text, Style::default().fg(theme.muted)));
    }
    frame.render_widget(Paragraph::new(lines), rows);
    let count = app.session.visible().len();
    let offset = app.packet_offset;
    scrollbar(
        frame,
        app,
        Pane::Packets,
        Rect::new(inner.x, rows.y, inner.width, rows.height),
        count,
        offset,
    );
}

pub fn details(frame: &mut Frame, app: &mut App, area: Rect) {
    let theme = app.theme;
    let inner = panel(
        frame,
        area,
        " PROTOCOL DETAILS ",
        if app.pane == Pane::Details {
            theme.green
        } else {
            theme.muted
        },
        theme,
    );
    let rows_area = Rect::new(
        inner.x,
        inner.y,
        inner.width.saturating_sub(1),
        inner.height,
    );
    app.regions.details = rows_area;
    let rows = app.detail_rows();
    app.detail_offset = app
        .detail_offset
        .min(rows.len().saturating_sub(rows_area.height as usize));
    let mut lines = Vec::new();
    for (index, &(layer_index, field_index)) in rows
        .iter()
        .enumerate()
        .skip(app.detail_offset)
        .take(rows_area.height as usize)
    {
        let layer = &app.layers[layer_index];
        let (text, style) = if let Some(field) = field_index {
            (
                format!("    {}", safe_text(&layer.fields[field].label)),
                Style::default().fg(theme.text),
            )
        } else {
            let arrow = if app.collapsed.contains(&layer_index) {
                "▸"
            } else {
                "▾"
            };
            (
                format!(
                    " {arrow} {}  [{}..{}]",
                    layer.label, layer.range.start, layer.range.end
                ),
                bold(theme.green),
            )
        };
        lines.push(Line::styled(
            text,
            if index == app.detail_selected {
                bold(theme.bg).bg(theme.green)
            } else {
                style
            },
        ));
    }
    if rows.is_empty() {
        lines.push(Line::styled(
            "Select a packet to inspect its fields.",
            Style::default().fg(theme.muted),
        ));
    }
    frame.render_widget(Paragraph::new(lines), rows_area);
    let offset = app.detail_offset;
    scrollbar(frame, app, Pane::Details, inner, rows.len(), offset);
}

pub fn bytes(frame: &mut Frame, app: &mut App, area: Rect) {
    let theme = app.theme;
    let inner = panel(
        frame,
        area,
        " HEX / ASCII · selected field highlighted ",
        if app.pane == Pane::Bytes {
            theme.purple
        } else {
            theme.muted
        },
        theme,
    );
    let rows_area = Rect::new(
        inner.x,
        inner.y,
        inner.width.saturating_sub(1),
        inner.height,
    );
    app.regions.bytes = rows_area;
    let width = app.bytes_per_line();
    let highlight = app.selected_range();
    let count = app
        .session
        .selected_packet()
        .map_or(0, |p| p.bytes.len().div_ceil(width));
    app.byte_offset = app
        .byte_offset
        .min(count.saturating_sub(rows_area.height as usize));
    let mut lines = Vec::new();
    if let Some(packet) = app.session.selected_packet() {
        for line_index in app.byte_offset..(app.byte_offset + rows_area.height as usize).min(count)
        {
            let start = line_index * width;
            let mut spans = vec![Span::styled(
                format!("{start:06x}  "),
                Style::default().fg(theme.muted),
            )];
            for column in 0..width {
                let index = start + column;
                let style = if highlight.contains(&index) {
                    bold(theme.bg).bg(theme.purple)
                } else {
                    Style::default().fg(theme.text)
                };
                spans.push(Span::styled(
                    packet
                        .bytes
                        .get(index)
                        .map_or_else(|| "   ".into(), |b| format!("{b:02x} ")),
                    style,
                ));
            }
            spans.push(Span::raw(" "));
            for (column, byte) in packet.bytes[start..packet.bytes.len().min(start + width)]
                .iter()
                .enumerate()
            {
                let style = if highlight.contains(&(start + column)) {
                    bold(theme.bg).bg(theme.purple)
                } else {
                    Style::default().fg(theme.green)
                };
                spans.push(Span::styled(
                    if (32..=126).contains(byte) {
                        char::from(*byte)
                    } else {
                        '.'
                    }
                    .to_string(),
                    style,
                ));
            }
            lines.push(Line::from(spans));
        }
    }
    frame.render_widget(Paragraph::new(lines), rows_area);
    let offset = app.byte_offset;
    scrollbar(frame, app, Pane::Bytes, inner, count, offset);
}

fn endpoint(summary: &Summary, source: bool) -> String {
    let (address, port) = if source {
        (summary.src, summary.src_port)
    } else {
        (summary.dst, summary.dst_port)
    };
    match (address, port) {
        (Some(address), Some(port)) if address.is_ipv6() => format!("[{address}]:{port}"),
        (Some(address), Some(port)) => format!("{address}:{port}"),
        (Some(address), _) => address.to_string(),
        _ => "—".into(),
    }
}

fn fit(text: &str, width: usize) -> String {
    let length = text.chars().count();
    if length > width {
        format!(
            "{}…",
            text.chars()
                .take(width.saturating_sub(1))
                .collect::<String>()
        )
    } else {
        format!("{text}{}", " ".repeat(width - length))
    }
}
