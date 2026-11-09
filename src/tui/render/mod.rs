mod dialogs;
mod panes;

use super::{
    app::{Action, App, Pane, Regions, TextInput},
    theme::Theme,
};
use crate::decode::safe_text;
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph, Sparkline},
    Frame,
};

pub fn draw(frame: &mut Frame, app: &mut App) {
    let area = frame.area();
    let theme = app.theme;
    app.regions = Regions::default();
    frame.render_widget(
        Block::default().style(Style::default().bg(theme.bg).fg(theme.text)),
        area,
    );
    if area.width < 60 || area.height < 22 {
        frame.render_widget(
            Paragraph::new("Resize to at least 60 × 22 for packet inspection.\nPress q to quit.")
                .style(Style::default().fg(theme.yellow)),
            area,
        );
        if area.height > 3 {
            button(
                frame,
                app,
                Rect::new(area.x, area.y + 3, 10.min(area.width), 1),
                "Quit",
                Action::Quit,
                true,
            );
        }
        return;
    }
    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(2),
        Constraint::Length(5),
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Min(4),
        Constraint::Length(2),
    ])
    .split(area);
    let source = app
        .source
        .as_ref()
        .map_or_else(|| "no source".into(), |s| safe_text(&s.label()));
    let state = if app.status.error.is_some() {
        "ERROR"
    } else if app.window_full {
        "WINDOW FULL"
    } else if app.worker.is_none() {
        "READY"
    } else if app.status.done {
        "FINISHED"
    } else if app.source.as_ref().is_some_and(|s| s.is_live()) {
        "LIVE"
    } else {
        "READING"
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" ◈ PACKETREAD ", bold(theme.cyan)),
            Span::styled(
                format!(" {state} "),
                bold(if state == "ERROR" {
                    theme.red
                } else {
                    theme.green
                }),
            ),
            Span::styled(format!("  {source}"), Style::default().fg(theme.muted)),
        ])),
        chunks[0],
    );
    toolbar(frame, app, chunks[1]);
    metrics(frame, app, chunks[2]);
    filter(frame, app, chunks[3]);
    tabs(frame, app, chunks[4]);
    app.regions.body = chunks[5];
    if area.width >= 110 && chunks[5].height >= 10 {
        let body = chunks[5];
        let top_height =
            (u32::from(body.height.saturating_sub(1)) * u32::from(app.table_percent) / 100) as u16;
        let top_height = top_height.clamp(4, body.height.saturating_sub(5));
        let bottom_y = body.y + top_height + 1;
        let bottom_height = body.height - top_height - 1;
        let left_width =
            (u32::from(body.width.saturating_sub(1)) * u32::from(app.details_percent) / 100) as u16;
        app.regions.horizontal = Rect::new(body.x, body.y + top_height, body.width, 1);
        app.regions.vertical = Rect::new(body.x + left_width, bottom_y, 1, bottom_height);
        frame.render_widget(
            Paragraph::new("─ drag to resize ─")
                .centered()
                .style(Style::default().fg(theme.muted)),
            app.regions.horizontal,
        );
        panes::packets(
            frame,
            app,
            Rect::new(body.x, body.y, body.width, top_height),
        );
        panes::details(
            frame,
            app,
            Rect::new(body.x, bottom_y, left_width, bottom_height),
        );
        panes::bytes(
            frame,
            app,
            Rect::new(
                body.x + left_width + 1,
                bottom_y,
                body.width - left_width - 1,
                bottom_height,
            ),
        );
    } else {
        match app.pane {
            Pane::Packets => panes::packets(frame, app, chunks[5]),
            Pane::Details => panes::details(frame, app, chunks[5]),
            Pane::Bytes => panes::bytes(frame, app, chunks[5]),
        }
    }
    let selected_warning = app
        .session
        .selected_packet()
        .and_then(|p| p.summary.warning.as_deref());
    let line = if app.status.error.is_some() || app.window_full {
        app.notice.as_str()
    } else {
        app.filter_error
            .as_deref()
            .or(selected_warning)
            .unwrap_or(&app.notice)
    };
    let foot = vec![Line::styled(safe_text(line), Style::default().fg(if selected_warning.is_some() || app.status.error.is_some() { theme.yellow } else { theme.muted })),
        Line::styled(" / filter  ·  Tab pane  ·  ↑↓/jk navigate  ·  Space follow  ·  ? help  ·  mouse enabled", Style::default().fg(theme.muted))];
    frame.render_widget(Paragraph::new(foot), chunks[6]);
    if app.dialog.is_some() {
        dialogs::draw(frame, app);
    }
}

fn toolbar(frame: &mut Frame, app: &mut App, area: Rect) {
    let active = app.worker.is_some() && !app.status.done;
    let live = app.source.as_ref().is_some_and(|s| s.is_live());
    let entries = [
        ("Open", Action::Open, true),
        ("Interfaces", Action::Interfaces, true),
        ("Start", Action::Start, !active),
        ("Stop", Action::Stop, active),
        (
            if app.session.follow {
                "Follow ●"
            } else {
                "Follow ○"
            },
            Action::Follow,
            true,
        ),
        ("Next", Action::NextWindow, app.window_full),
        ("BPF", Action::Bpf, live),
        ("Theme", Action::Theme, true),
        ("Help", Action::Help, true),
        ("Quit", Action::Quit, true),
    ];
    let (mut x, mut y) = (area.x, area.y);
    for (label, action, enabled) in entries {
        let width = Line::raw(label).width() as u16 + 4;
        if x + width > area.right() {
            x = area.x;
            y += 1;
        }
        if y >= area.bottom() {
            break;
        }
        button(
            frame,
            app,
            Rect::new(x, y, width, 1),
            label,
            action,
            enabled,
        );
        x += width + 1;
    }
}

fn metrics(frame: &mut Frame, app: &App, area: Rect) {
    let theme = app.theme;
    let chunks = Layout::horizontal([
        Constraint::Percentage(25),
        Constraint::Percentage(25),
        Constraint::Percentage(25),
        Constraint::Percentage(25),
    ])
    .split(area);
    let summary = vec![
        Line::styled(format!("{} packets", app.status.packets), bold(theme.cyan)),
        Line::from(format!("{} visible", app.session.visible.len())),
        Line::styled(
            format!("{} retained", app.session.len()),
            Style::default().fg(theme.muted),
        ),
    ];
    frame.render_widget(
        Paragraph::new(summary)
            .block(block(" CAPTURE ", theme.cyan, theme))
            .style(Style::default().fg(theme.text)),
        chunks[0],
    );
    let pps: Vec<_> = app.packet_history.iter().copied().collect();
    let bps: Vec<_> = app.byte_history.iter().copied().collect();
    frame.render_widget(
        Sparkline::default()
            .block(block(
                format!(" {} pkt/s ", app.packet_rate),
                theme.green,
                theme,
            ))
            .data(&pps)
            .style(Style::default().fg(theme.green)),
        chunks[1],
    );
    frame.render_widget(
        Sparkline::default()
            .block(block(
                format!(" {}/s ", size(app.byte_rate)),
                theme.purple,
                theme,
            ))
            .data(&bps)
            .style(Style::default().fg(theme.purple)),
        chunks[2],
    );
    let drops = app
        .status
        .kernel_drops
        .map_or_else(|| "n/a".into(), |n| n.to_string());
    let loss_color = if app.status.app_drops > 0 || app.status.kernel_drops.unwrap_or(0) > 0 {
        theme.red
    } else {
        theme.yellow
    };
    let status = vec![
        Line::styled(
            format!("app {} · OS {drops}", app.status.app_drops),
            Style::default().fg(loss_color),
        ),
        Line::from(format!(
            "{} / {}",
            size(app.session.bytes as u64),
            size(app.session.byte_limit as u64)
        )),
        Line::styled(
            format!("{} evicted", app.session.evicted),
            Style::default().fg(theme.muted),
        ),
    ];
    frame.render_widget(
        Paragraph::new(status)
            .block(block(" DROPS / MEMORY ", loss_color, theme))
            .style(Style::default().fg(theme.text)),
        chunks[3],
    );
}

fn filter(frame: &mut Frame, app: &mut App, area: Rect) {
    let theme = app.theme;
    let color = if app.filter_error.is_some() {
        theme.red
    } else if app.editing_filter {
        theme.green
    } else {
        theme.cyan
    };
    let title = if app.session.filtering {
        " DISPLAY FILTER · rebuilding… "
    } else {
        " DISPLAY FILTER · proto=tcp port=443 "
    };
    let inner = panel(frame, area, title, color, theme);
    let input_area = Rect::new(
        inner.x,
        inner.y,
        inner.width.saturating_sub(10),
        inner.height,
    );
    app.regions.buttons.push((input_area, Action::Filter));
    input(frame, input_area, &app.filter, app.editing_filter, theme);
    button(
        frame,
        app,
        Rect::new(inner.right().saturating_sub(9), inner.y, 9, 1),
        "Apply",
        Action::ApplyFilter,
        true,
    );
}

fn tabs(frame: &mut Frame, app: &mut App, area: Rect) {
    for (index, (pane, title)) in [
        (Pane::Packets, "1 Packets"),
        (Pane::Details, "2 Details"),
        (Pane::Bytes, "3 Bytes"),
    ]
    .into_iter()
    .enumerate()
    {
        let rect = Rect::new(area.x + index as u16 * 15, area.y, 14, 1);
        let color = if pane == app.pane {
            app.theme.cyan
        } else {
            app.theme.muted
        };
        frame.render_widget(
            Paragraph::new(format!("[ {title} ]")).style(bold(color)),
            rect,
        );
        app.regions.buttons.push((rect, Action::Focus(pane)));
    }
}

pub(super) fn button(
    frame: &mut Frame,
    app: &mut App,
    area: Rect,
    label: &str,
    action: Action,
    enabled: bool,
) {
    let color = if enabled {
        app.theme.cyan
    } else {
        app.theme.muted
    };
    frame.render_widget(
        Paragraph::new(format!("[ {label} ]")).style(if enabled {
            bold(color).bg(app.theme.panel)
        } else {
            Style::default().fg(color)
        }),
        area,
    );
    if enabled {
        app.regions.buttons.push((area, action));
    }
}

pub(super) fn block(title: impl Into<String>, color: Color, theme: Theme) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(color))
        .title(Line::styled(title.into(), bold(color)))
        .style(Style::default().bg(theme.panel))
}

pub(super) fn panel(
    frame: &mut Frame,
    area: Rect,
    title: impl Into<String>,
    color: Color,
    theme: Theme,
) -> Rect {
    let block = block(title, color, theme);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    inner
}
pub(super) fn bold(color: Color) -> Style {
    Style::default().fg(color).add_modifier(Modifier::BOLD)
}
pub(super) fn size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

pub(super) fn input(frame: &mut Frame, area: Rect, input: &TextInput, focused: bool, theme: Theme) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let mut start = 0;
    while Line::raw(&input.value[start..input.cursor]).width() >= usize::from(area.width) {
        let Some(c) = input.value[start..].chars().next() else {
            break;
        };
        start += c.len_utf8();
    }
    frame.render_widget(
        Paragraph::new(safe_text(&input.value[start..])).style(Style::default().fg(theme.text)),
        area,
    );
    if focused {
        let column = Line::raw(safe_text(&input.value[start..input.cursor])).width() as u16;
        frame.set_cursor_position((area.x + column.min(area.width - 1), area.y));
    }
}

pub(super) fn scrollbar(
    frame: &mut Frame,
    app: &mut App,
    pane: Pane,
    area: Rect,
    count: usize,
    offset: usize,
) {
    if area.height == 0 || area.width == 0 {
        return;
    }
    let rect = Rect::new(area.right() - 1, area.y, 1, area.height);
    app.regions.scrollbars.push((rect, pane));
    let max_offset = count.saturating_sub(area.height as usize);
    let thumb = (offset.min(max_offset) * usize::from(area.height - 1))
        .checked_div(max_offset)
        .unwrap_or(0);
    let lines: Vec<_> = (0..area.height)
        .map(|row| {
            Line::styled(
                if row as usize == thumb { "█" } else { "│" },
                Style::default().fg(if row as usize == thumb {
                    app.theme.cyan
                } else {
                    app.theme.muted
                }),
            )
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), rect);
}
