use super::{bold, panel, scrollbar};
use crate::{
    decode::{safe_text, Summary},
    session::Session,
    tui::app::{App, Pane, TimeFormat},
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
    let (time_label, time_width) = match app.time_format {
        TimeFormat::Clock => ("TIME UTC", 15),
        TimeFormat::Relative if app.time_reference.is_some() => ("SINCE REFERENCE", 15),
        TimeFormat::Relative => ("SINCE FIRST", 15),
        TimeFormat::Delta => ("SINCE PREVIOUS", 15),
        TimeFormat::Date => ("DATE UTC", 19),
    };
    const COLUMN: usize = 18;
    let header = if wide {
        let extra: String = app
            .columns
            .iter()
            .map(|(title, ..)| format!("{:<COLUMN$} ", title.to_ascii_uppercase()))
            .collect();
        format!(
            " {:>7} {:>time_width$} {:<26} {:<26} {:<7} {:>6}  {extra}INFO",
            "NO.", time_label, "SOURCE", "DESTINATION", "PROTO", "LEN"
        )
    } else {
        format!(
            " {:>6} {:<16} {:<16} {:<6} {:>5}",
            "NO.", "SOURCE", "DESTINATION", "PROTO", "LEN"
        )
    };
    frame.render_widget(
        Paragraph::new(header).style(bold(theme.muted)),
        Rect::new(inner.x, inner.y, inner.width, inner.height.min(1)),
    );
    let mut lines = Vec::new();
    let names = app.resolve.then_some(&app.session);
    let first = app
        .time_reference
        .map(|(_, time)| time)
        .or_else(|| app.session.packets().next().map(|p| p.timestamp_ns))
        .unwrap_or(0);
    let shift = app.time_shift_ns;
    let visible = app.session.visible();
    for (index, id) in visible
        .iter()
        .enumerate()
        .skip(app.packet_offset)
        .take(rows.height as usize)
    {
        if let Some(packet) = app.session.packet(*id) {
            let summary = &packet.summary;
            let source = fit(&endpoint(summary, true, names), endpoint_width);
            let destination = fit(&endpoint(summary, false, names), endpoint_width);
            let seconds = |ns: i128| format!("{:.6}", ns as f64 / 1e9);
            let time = match app.time_format {
                TimeFormat::Clock => clock(packet.timestamp_ns + shift).1,
                TimeFormat::Date => {
                    let (date, time) = clock(packet.timestamp_ns + shift);
                    format!("{date} {}", &time[..8])
                }
                TimeFormat::Relative => seconds(packet.timestamp_ns - first),
                TimeFormat::Delta => {
                    let previous = index
                        .checked_sub(1)
                        .and_then(|i| app.session.packet(visible[i]));
                    seconds(previous.map_or(0, |p| packet.timestamp_ns - p.timestamp_ns))
                }
            };
            let mark = match (packet.mark, packet.comment.is_some()) {
                _ if app.time_reference.is_some_and(|(id, _)| id == packet.id) => 'R',
                (true, _) => '*',
                (false, true) => '#',
                _ => ' ',
            };
            // The first matching coloring rule colors the row's text.
            let rule = app
                .colors
                .iter()
                .find(|(_, _, filter)| filter.matches(packet))
                .map(|(color, ..)| theme.rule(color));
            let text_color = rule.unwrap_or(theme.text);
            let lead = if wide {
                format!("{mark}{id:>7} {time:>time_width$} {source} {destination} ")
            } else {
                format!("{mark}{:>6} {source} {destination} ", id)
            };
            let mut spans = vec![
                Span::styled(lead, Style::default().fg(text_color)),
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
                for (_, _, field) in &app.columns {
                    let value = field.value(packet).unwrap_or_default();
                    spans.push(Span::styled(
                        format!("{} ", fit(&safe_text(&value), COLUMN)),
                        Style::default().fg(theme.green),
                    ));
                }
                spans.push(Span::styled(
                    safe_text(&summary.info),
                    Style::default().fg(match rule {
                        Some(color) => color,
                        None if summary.diag != 0 => theme.yellow,
                        None => theme.text,
                    }),
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
                    safe_text(&layer.label),
                    layer.range.start,
                    layer.range.end
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
    let reassembled = app
        .session
        .selected_packet()
        .is_some_and(|p| p.reassembled.is_some());
    let inner = panel(
        frame,
        area,
        if reassembled {
            " HEX / ASCII · reassembled IP datagram "
        } else {
            " HEX / ASCII · selected field highlighted "
        },
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
        .map_or(0, |p| p.view().0.len().div_ceil(width));
    app.byte_offset = app
        .byte_offset
        .min(count.saturating_sub(rows_area.height as usize));
    let mut lines = Vec::new();
    if let Some(bytes) = app.session.selected_packet().map(|p| p.view().0) {
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
                    bytes
                        .get(index)
                        .map_or_else(|| "   ".into(), |b| format!("{b:02x} ")),
                    style,
                ));
            }
            spans.push(Span::raw(" "));
            for (column, byte) in bytes[start..bytes.len().min(start + width)]
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

fn endpoint(summary: &Summary, source: bool, names: Option<&Session>) -> String {
    let (address, port) = if source {
        (summary.src, summary.src_port)
    } else {
        (summary.dst, summary.dst_port)
    };
    let name = address.and_then(|address| names?.name(&address));
    match (address, port, name) {
        (_, Some(port), Some(name)) => format!("{}:{port}", safe_text(name)),
        (_, None, Some(name)) => safe_text(name),
        (Some(address), Some(port), _) if address.is_ipv6() => format!("[{address}]:{port}"),
        (Some(address), Some(port), _) => format!("{address}:{port}"),
        (Some(address), _, _) => address.to_string(),
        _ => "—".into(),
    }
}

/// UTC date (`YYYY-MM-DD`) and time of day (`HH:MM:SS.ffffff`).
fn clock(timestamp_ns: i128) -> (String, String) {
    let seconds = timestamp_ns.div_euclid(1_000_000_000);
    let micros = timestamp_ns.rem_euclid(1_000_000_000) / 1000;
    let (days, day) = (seconds.div_euclid(86_400), seconds.rem_euclid(86_400));
    // Civil date from a day count (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let (d, m) = (
        doy - (153 * mp + 2) / 5 + 1,
        if mp < 10 { mp + 3 } else { mp - 9 },
    );
    let year = yoe + era * 400 + i128::from(m <= 2);
    (
        format!("{year:04}-{m:02}-{d:02}"),
        format!(
            "{:02}:{:02}:{:02}.{micros:06}",
            day / 3600,
            day / 60 % 60,
            day % 60
        ),
    )
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

#[cfg(test)]
mod tests {
    #[test]
    fn clock_formats_utc_dates() {
        let stamp = |ns: i128| super::clock(ns);
        assert_eq!(stamp(0), ("1970-01-01".into(), "00:00:00.000000".into()));
        assert_eq!(
            stamp(1_700_000_000_012_500_000),
            ("2023-11-14".into(), "22:13:20.012500".into())
        );
        assert_eq!(stamp(951_782_400_000_000_000).0, "2000-02-29");
        assert_eq!(
            stamp(-1_000_000_000),
            ("1969-12-31".into(), "23:59:59.000000".into())
        );
    }
}
