//! The Stats screen: the displayed packets as an overview and ranked tables.
use super::{bold, panel};
use crate::{
    decode::safe_text,
    stats::{size, Direction, Unit},
    tui::{
        app::{reveal, Action, App},
        dashboard::{Command, Dashboard, Row, Tab},
        theme::Theme,
    },
};
use ratatui::{
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Paragraph, Sparkline},
    Frame,
};
use std::ops::Range;

/// Widest share bar, in columns.
const BAR: usize = 24;

pub fn draw(frame: &mut Frame, app: &mut App, mut area: Rect) {
    let theme = app.theme;
    let muted = Style::default().fg(theme.muted);
    // Taken out so the tables can record their scroll position while drawing.
    let Some(mut d) = app.stats.take() else {
        frame.render_widget(
            Paragraph::new(" Display filter is updating · statistics follow").style(muted),
            area,
        );
        return;
    };
    let stats = &d.stats;
    let seconds = stats
        .first_ns
        .map_or(0.0, |first| (stats.last_ns - first) as f64 / 1e9);
    let mut header = vec![Span::styled(
        format!(
            " Stats · {} · {} packets · {} · {seconds:.1} s",
            d.scope,
            stats.total.packets,
            size(stats.total.bytes)
        ),
        bold(theme.text),
    )];
    if app.session.filtering() {
        header.push(Span::styled(
            " · display filter updating…",
            Style::default().fg(theme.yellow),
        ));
    }
    let mut lines = vec![Line::from(header)];
    if !d.message.is_empty() && area.height > 6 {
        lines.push(Line::styled(
            format!(" {}", safe_text(&d.message)),
            Style::default().fg(theme.yellow),
        ));
    }
    let used = lines.len() as u16;
    frame.render_widget(
        Paragraph::new(lines),
        Rect {
            height: used,
            ..area
        },
    );
    area.y += used;
    area.height -= used;
    if d.tab == Tab::Overview && area.width >= 96 && area.height >= 12 {
        overview(frame, app, &mut d, area);
    } else {
        list(frame, app, &mut d, area);
    }
    app.stats = Some(d);
}

/// A share of `width` columns, drawn in eighths so small shares stay visible.
fn bar(share: f64, width: usize) -> String {
    const PARTS: [char; 7] = ['▏', '▎', '▍', '▌', '▋', '▊', '▉'];
    let eighths = (share.clamp(0.0, 1.0) * (width * 8) as f64).round() as usize;
    let eighths = eighths.max(usize::from(share > 0.0));
    let mut bar = "█".repeat(eighths / 8);
    if !eighths.is_multiple_of(8) {
        bar.push(PARTS[eighths % 8 - 1]);
    }
    bar
}

fn chars(text: &str) -> usize {
    text.chars().count()
}

/// Draws one selectable row and makes it clickable.
fn row_line(
    frame: &mut Frame,
    app: &mut App,
    area: Rect,
    index: usize,
    selected: bool,
    spans: Vec<Span<'static>>,
) {
    let theme = app.theme;
    let line = if selected {
        let text: String = spans.iter().map(|span| span.content.as_ref()).collect();
        Line::raw(format!("▌{text}"))
    } else {
        let mut all = vec![Span::raw(" ")];
        all.extend(spans);
        Line::from(all)
    };
    let style = if selected {
        bold(theme.bg).bg(theme.cyan)
    } else {
        Style::default().fg(theme.text)
    };
    frame.render_widget(Paragraph::new(line).style(style), area);
    app.regions
        .buttons
        .push((area, Action::Dashboard(Command::Open(index))));
}

/// `Label: [Active] Other (key)`, with the active option highlighted.
fn choice(theme: Theme, label: &str, options: &[(&str, bool)], key: char) -> Vec<Span<'static>> {
    let muted = Style::default().fg(theme.muted);
    let mut spans = vec![Span::styled(format!("{label}: "), muted)];
    for (name, active) in options {
        spans.push(if *active {
            Span::styled(format!("[{name}] "), bold(theme.cyan))
        } else {
            Span::styled(format!("{name} "), muted)
        });
    }
    spans.push(Span::styled(format!("({key})"), muted));
    spans
}

/// The settings line above a table. Returns whether it drew anything.
fn controls(frame: &mut Frame, app: &mut App, d: &Dashboard, area: Rect) -> bool {
    let theme = app.theme;
    let muted = Style::default().fg(theme.muted);
    let rank = || {
        (
            choice(
                theme,
                "Rank",
                &[
                    ("Bytes", d.unit == Unit::Bytes),
                    ("Packets", d.unit == Unit::Packets),
                ],
                'u',
            ),
            Some(Command::Unit),
        )
    };
    let segments = match d.tab {
        Tab::Ips => vec![
            rank(),
            (
                choice(
                    theme,
                    "Direction",
                    &[
                        ("Both", d.direction == Direction::Both),
                        ("Sent", d.direction == Direction::Sent),
                        ("Received", d.direction == Direction::Received),
                    ],
                    'd',
                ),
                Some(Command::Direction),
            ),
        ],
        Tab::Overview | Tab::Protocols => vec![rank()],
        Tab::Conversations => match d.address {
            Some(ip) => vec![
                (
                    vec![
                        Span::styled("Address ", muted),
                        Span::styled(ip.to_string(), bold(theme.text)),
                    ],
                    None,
                ),
                (
                    vec![Span::styled("[ ✕ all (x) ]", bold(theme.cyan))],
                    Some(Command::Unscope),
                ),
                (
                    vec![Span::styled("[ its packets (p) ]", bold(theme.cyan))],
                    Some(Command::Packets),
                ),
            ],
            None => vec![(
                vec![Span::styled("Busiest streams of every address", muted)],
                None,
            )],
        },
        Tab::Issues => vec![(
            vec![Span::styled(
                "Enter opens the first packet · p lists them all",
                muted,
            )],
            None,
        )],
    };
    let mut x = area.x;
    for (spans, command) in segments {
        let line = Line::from(spans);
        let width = (line.width() as u16).min(area.right().saturating_sub(x));
        if width == 0 {
            break;
        }
        let rect = Rect::new(x, area.y, width, 1);
        frame.render_widget(Paragraph::new(line), rect);
        if let Some(command) = command {
            app.regions.buttons.push((rect, Action::Dashboard(command)));
        }
        x += width + 3;
    }
    true
}

/// One tab as a panel: settings, column titles and the ranked rows.
fn list(frame: &mut Frame, app: &mut App, d: &mut Dashboard, area: Rect) {
    let theme = app.theme;
    let mut title = format!(" {}", d.tab.title());
    if let (Tab::Conversations, Some(ip)) = (d.tab, d.address) {
        title += &format!(" · {ip}");
    }
    if !d.rows.is_empty() {
        title += &format!(" · {} / {}", d.selected + 1, d.rows.len());
        if d.available > d.rows.len() {
            title += &format!(" · top {} of {}", d.rows.len(), d.available);
        }
    }
    let inner = panel(frame, area, title + " ", theme.cyan, theme);
    let mut inner = Rect::new(
        inner.x + 1,
        inner.y,
        inner.width.saturating_sub(2),
        inner.height,
    );
    if inner.height >= 6 && controls(frame, app, d, Rect { height: 1, ..inner }) {
        inner.y += 1;
        inner.height -= 1;
    }
    table(frame, app, d, inner);
}

fn table(frame: &mut Frame, app: &mut App, d: &mut Dashboard, area: Rect) {
    if area.height < 2 || area.width == 0 {
        return;
    }
    let theme = app.theme;
    let widths: Vec<usize> = d
        .columns
        .iter()
        .enumerate()
        .map(|(index, column)| {
            d.rows
                .iter()
                .map(|row| chars(&row.cells[index]))
                .max()
                .unwrap_or(0)
                .max(chars(column.title))
        })
        .collect();
    // Columns are dropped, least important first, until the rest fit.
    let mut shown: Vec<usize> = (0..d.columns.len()).collect();
    let needed = |shown: &[usize]| 1 + shown.iter().map(|&i| widths[i] + 2).sum::<usize>();
    while needed(&shown) > usize::from(area.width) {
        let droppable = shown
            .iter()
            .enumerate()
            .filter(|(_, &column)| d.columns[column].drop > 0)
            .max_by_key(|(_, &column)| d.columns[column].drop);
        let Some((position, _)) = droppable else {
            break;
        };
        shown.remove(position);
    }
    let spare = usize::from(area.width).saturating_sub(needed(&shown) + 2);
    let bar_after = d
        .bar_after
        .filter(|column| shown.contains(column) && spare >= 6);
    let bar_width = spare.min(BAR);
    let cell = |column: usize, text: &str| {
        let width = widths[column];
        if d.columns[column].right {
            format!("{text:>width$}  ")
        } else {
            format!("{text:<width$}  ")
        }
    };
    let mut titles = String::from(" ");
    for &column in &shown {
        titles += &cell(column, d.columns[column].title);
        if bar_after == Some(column) {
            titles += &" ".repeat(bar_width + 2);
        }
    }
    frame.render_widget(
        Paragraph::new(titles).style(bold(theme.muted)),
        Rect { height: 1, ..area },
    );
    let height = usize::from(area.height - 1);
    d.page_rows = height;
    reveal(&mut d.offset, d.selected, height);
    d.offset = d.offset.min(d.rows.len().saturating_sub(height));
    for (index, row) in d.rows.iter().enumerate().skip(d.offset).take(height) {
        let mut spans = Vec::new();
        for &column in &shown {
            spans.push(Span::raw(cell(column, &safe_text(&row.cells[column]))));
            if bar_after == Some(column) {
                let bar = bar(row.share.unwrap_or(0.0), bar_width);
                spans.push(Span::styled(
                    format!("{bar:<bar_width$}  "),
                    Style::default().fg(theme.cyan),
                ));
            }
        }
        let y = area.y + 1 + (index - d.offset) as u16;
        row_line(
            frame,
            app,
            Rect::new(area.x, y, area.width, 1),
            index,
            index == d.selected,
            spans,
        );
    }
}

/// Selectable rows of one Overview panel, scrolled to keep the selection in view.
fn panel_rows(
    frame: &mut Frame,
    app: &mut App,
    d: &Dashboard,
    area: Rect,
    range: Range<usize>,
    spans: impl Fn(&Row) -> Vec<Span<'static>>,
) {
    let height = usize::from(area.height);
    let mut offset = 0;
    if range.contains(&d.selected) {
        reveal(&mut offset, d.selected - range.start, height);
    }
    for (line, index) in range.skip(offset).take(height).enumerate() {
        row_line(
            frame,
            app,
            Rect::new(area.x, area.y + line as u16, area.width, 1),
            index,
            index == d.selected,
            spans(&d.rows[index]),
        );
    }
}

fn padded(frame: &mut Frame, area: Rect, title: String, color: Color, theme: Theme) -> Rect {
    let inner = panel(frame, area, title, color, theme);
    Rect::new(
        inner.x + 1,
        inner.y,
        inner.width.saturating_sub(2),
        inner.height,
    )
}

/// Traffic, top talkers, protocols and TCP issues side by side.
fn overview(frame: &mut Frame, app: &mut App, d: &mut Dashboard, area: Rect) {
    let theme = app.theme;
    let muted = Style::default().fg(theme.muted);
    let unit = d.unit;
    let left_width = area.width / 2;
    let left = Rect {
        width: left_width,
        ..area
    };
    let right = Rect {
        x: area.x + left_width,
        width: area.width - left_width,
        ..area
    };
    let issue_count = d.rows.len() - d.talkers;
    let issues_height = (issue_count as u16 + 2).clamp(4, right.height / 2);
    let traffic_area = Rect { height: 6, ..left };
    let talkers_area = Rect {
        y: left.y + 6,
        height: left.height - 6,
        ..left
    };
    let protocols_area = Rect {
        height: right.height - issues_height,
        ..right
    };
    let issues_area = Rect {
        y: protocols_area.bottom(),
        height: issues_height,
        ..right
    };

    let stats = &d.stats;
    let values: Vec<u64> = stats.buckets.iter().map(|c| unit.value(*c)).collect();
    // More intervals than columns: each column sums a run of them.
    let run = values
        .len()
        .div_ceil(usize::from(traffic_area.width.saturating_sub(4)).max(1))
        .max(1);
    let interval = run as f64 * stats.interval_ns as f64 / 1e9;
    let inner = padded(
        frame,
        traffic_area,
        format!(" Traffic · {} per {interval} s ", unit.label()),
        theme.green,
        theme,
    );
    let columns: Vec<u64> = values.chunks(run).map(|run| run.iter().sum()).collect();
    frame.render_widget(
        Sparkline::default()
            .data(&columns)
            .style(Style::default().fg(theme.green)),
        Rect {
            height: inner.height.saturating_sub(1),
            ..inner
        },
    );
    let peak = columns.iter().max().copied().unwrap_or(0);
    let seconds = stats
        .first_ns
        .map_or(0.0, |first| (stats.last_ns - first) as f64 / 1e9);
    let mut caption = format!("peak {} in {interval} s", unit.format(peak));
    if seconds >= 1.0 {
        let average = (unit.value(stats.total) as f64 / seconds) as u64;
        caption += &format!(" · average {} / s", unit.format(average));
    }
    frame.render_widget(
        Paragraph::new(caption).style(muted),
        Rect {
            y: inner.bottom().saturating_sub(1),
            height: 1,
            ..inner
        },
    );

    let inner = padded(
        frame,
        protocols_area,
        format!(" Protocols · by {} ", unit.label()),
        theme.purple,
        theme,
    );
    let ranked = stats.ranked_protocols(unit);
    let name_width = ranked
        .iter()
        .map(|(name, _)| chars(name))
        .max()
        .unwrap_or(0);
    let bar_width = usize::from(inner.width)
        .saturating_sub(name_width + 24)
        .min(BAR);
    let total = unit.value(stats.total).max(1);
    let lines: Vec<Line> = ranked
        .iter()
        .take(usize::from(inner.height))
        .map(|(name, counter)| {
            let share = unit.value(*counter) as f64 / total as f64;
            Line::from(vec![
                Span::raw(format!(" {name:<name_width$}  ")),
                Span::styled(
                    format!("{:<bar_width$}", bar(share, bar_width)),
                    Style::default().fg(theme.purple),
                ),
                Span::raw(format!(
                    " {:>5.1}% {:>12}",
                    100.0 * share,
                    unit.format(unit.value(*counter))
                )),
            ])
        })
        .collect();
    frame.render_widget(
        Paragraph::new(lines).style(Style::default().fg(theme.text)),
        inner,
    );

    let inner = padded(
        frame,
        talkers_area,
        format!(" Top talkers · by {} ", unit.label()),
        theme.cyan,
        theme,
    );
    let rows = &d.rows[..d.talkers];
    let name_width = rows.iter().map(|r| chars(&r.cells[0])).max().unwrap_or(0);
    let amount_width = rows.iter().map(|r| chars(&r.cells[1])).max().unwrap_or(0);
    let bar_width = usize::from(inner.width)
        .saturating_sub(name_width + amount_width + 14)
        .min(BAR);
    d.page_rows = usize::from(inner.height);
    panel_rows(frame, app, d, inner, 0..d.talkers, |row| {
        let Some(share) = row.share else {
            return vec![Span::styled(row.cells[0].clone(), bold(theme.cyan))];
        };
        vec![
            Span::raw(format!("{:<name_width$}  ", row.cells[0])),
            Span::styled(
                format!("{:<bar_width$}", bar(share, bar_width)),
                Style::default().fg(theme.cyan),
            ),
            Span::raw(format!(
                " {:>6} {:>amount_width$}",
                row.cells[2], row.cells[1]
            )),
        ]
    });

    let inner = padded(
        frame,
        issues_area,
        " TCP issues ".into(),
        if issue_count > 0 {
            theme.yellow
        } else {
            theme.green
        },
        theme,
    );
    if issue_count == 0 {
        frame.render_widget(
            Paragraph::new(" No TCP problems observed").style(muted),
            inner,
        );
    }
    let rows = &d.rows[d.talkers..];
    let name_width = rows.iter().map(|r| chars(&r.cells[0])).max().unwrap_or(0);
    let count_width = rows.iter().map(|r| chars(&r.cells[1])).max().unwrap_or(0);
    panel_rows(frame, app, d, inner, d.talkers..d.rows.len(), |row| {
        vec![
            Span::styled("● ", Style::default().fg(theme.yellow)),
            Span::raw(format!(
                "{:<name_width$}  {:>count_width$}  ",
                row.cells[0], row.cells[1]
            )),
            Span::styled(row.cells[2].clone(), muted),
        ]
    });
}
