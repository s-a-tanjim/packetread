mod dialogs;
mod panes;
mod stats;

use super::{
    app::{Action, App, Pane, Regions, Screen, TextInput},
    dashboard::{Command as DashboardCommand, Tab},
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
use std::collections::VecDeque;

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
    let entries = toolbar_entries(app);
    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(toolbar_rows(&entries, area.width)),
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
    let state = if app.ingest.status.error.is_some() {
        "ERROR"
    } else if app.searching() {
        "SEARCHING"
    } else if app.ingest.status.limit_reached {
        "LIMIT REACHED"
    } else if app.ingest.window_full {
        "WINDOW FULL"
    } else if !app.ingest.has_worker() {
        "READY"
    } else if app.ingest.status.done {
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
    toolbar(frame, app, chunks[1], entries);
    metrics(frame, app, chunks[2]);
    filter(frame, app, chunks[3]);
    tabs(frame, app, chunks[4]);
    app.regions.body = chunks[5];
    let stats = app.screen == Screen::Stats;
    if stats {
        stats::draw(frame, app, chunks[5]);
    } else if area.width >= 110 && chunks[5].height >= 10 {
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
        .filter(|_| !stats)
        .and_then(|p| p.summary.warning.as_deref());
    let line = if app.ingest.status.error.is_some() || app.ingest.window_full {
        app.notice.as_str()
    } else {
        app.filter_error
            .as_deref()
            .or(selected_warning)
            .unwrap_or(&app.notice)
    };
    let foot = vec![
        Line::styled(
            safe_text(line),
            Style::default().fg(
                if selected_warning.is_some() || app.ingest.status.error.is_some() {
                    theme.yellow
                } else {
                    theme.muted
                },
            ),
        ),
        Line::styled(
            if stats {
                stats_hint(app)
            } else {
                " / filter · a filter on selection · f find · m mark · w save · S stats · E expert · F stream · ? help"
            },
            Style::default().fg(theme.muted),
        ),
    ];
    frame.render_widget(Paragraph::new(foot), chunks[6]);
    if app.dialog.is_some() {
        dialogs::draw(frame, app);
    }
}

fn toolbar_entries(app: &App) -> Vec<(&'static str, Action, bool)> {
    let active = app.ingest.has_worker() && !app.ingest.status.done;
    let live = app.source.as_ref().is_some_and(|s| s.is_live());
    let any = !app.session.is_empty();
    vec![
        ("Open", Action::Open, true),
        ("Interfaces", Action::Interfaces, true),
        ("Start", Action::Start, !active),
        ("Stop", Action::Stop, active),
        ("Prev", Action::PrevWindow, !live && app.source.is_some()),
        ("Next", Action::NextWindow, app.ingest.window_full),
        (
            if app.session.follow() {
                "Auto-scroll ON"
            } else {
                "Auto-scroll OFF"
            },
            Action::Follow,
            true,
        ),
        ("BPF", Action::Bpf, live),
        ("Find", Action::Find, any),
        ("Save", Action::Export(false), any),
        (
            // The button names the screen it switches to.
            if app.screen == Screen::Stats {
                "Inspect"
            } else {
                "Stats"
            },
            Action::Stats,
            any,
        ),
        ("Stream", Action::FollowStream, any),
        ("Theme", Action::Theme, true),
        ("Help", Action::Help, true),
        ("Quit", Action::Quit, true),
    ]
}

/// Positions of the wrapped toolbar buttons, relative to the toolbar origin.
fn toolbar_layout(entries: &[(&'static str, Action, bool)], width: u16) -> Vec<(u16, u16, u16)> {
    let (mut x, mut y) = (0, 0);
    entries
        .iter()
        .map(|(label, _, _)| {
            let button = Line::raw(*label).width() as u16 + 4;
            if x > 0 && x + button > width {
                (x, y) = (0, y + 1);
            }
            x += button + 1;
            (x - button - 1, y, button)
        })
        .collect()
}

fn toolbar_rows(entries: &[(&'static str, Action, bool)], width: u16) -> u16 {
    let last = toolbar_layout(entries, width)
        .last()
        .map_or(0, |(_, y, _)| *y);
    (last + 1).clamp(2, 4)
}

fn toolbar(
    frame: &mut Frame,
    app: &mut App,
    area: Rect,
    entries: Vec<(&'static str, Action, bool)>,
) {
    let layout = toolbar_layout(&entries, area.width);
    for ((label, action, enabled), (x, y, width)) in entries.into_iter().zip(layout) {
        if y >= area.height {
            break;
        }
        button(
            frame,
            app,
            Rect::new(area.x + x, area.y + y, width.min(area.width), 1),
            label,
            action,
            enabled,
        );
    }
}

/// The newest samples that fit inside a bordered chart, one per column, so the
/// chart fills its panel at any terminal width with the latest sample at the right edge.
fn recent_samples(history: &VecDeque<u64>, area: Rect) -> Vec<u64> {
    let width = usize::from(area.width.saturating_sub(2));
    history
        .iter()
        .skip(history.len().saturating_sub(width))
        .copied()
        .collect()
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
        Line::styled(
            format!("{} packets", app.ingest.status.packets),
            bold(theme.cyan),
        ),
        Line::from(format!("{} visible", app.session.visible().len())),
        Line::styled(
            if app.ingest.status.saved > 0 {
                format!(
                    "{} retained · {} saved",
                    app.session.len(),
                    app.ingest.status.saved
                )
            } else {
                format!("{} retained", app.session.len())
            },
            Style::default().fg(theme.muted),
        ),
    ];
    frame.render_widget(
        Paragraph::new(summary)
            .block(block(" CAPTURE ", theme.cyan, theme))
            .style(Style::default().fg(theme.text)),
        chunks[0],
    );
    let pps = recent_samples(&app.ingest.packet_history, chunks[1]);
    let bps = recent_samples(&app.ingest.byte_history, chunks[2]);
    frame.render_widget(
        Sparkline::default()
            .block(block(
                format!(" {} pkt/s ", app.ingest.packet_rate),
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
                format!(" {}/s ", size(app.ingest.byte_rate)),
                theme.purple,
                theme,
            ))
            .data(&bps)
            .style(Style::default().fg(theme.purple)),
        chunks[2],
    );
    let drops = app
        .ingest
        .status
        .kernel_drops
        .map_or_else(|| "n/a".into(), |n| n.to_string());
    let loss_color =
        if app.ingest.status.app_drops > 0 || app.ingest.status.kernel_drops.unwrap_or(0) > 0 {
            theme.red
        } else {
            theme.yellow
        };
    let status = vec![
        Line::styled(
            format!("app {} · OS {drops}", app.ingest.status.app_drops),
            Style::default().fg(loss_color),
        ),
        Line::from(format!(
            "{} / {}",
            size(app.session.bytes() as u64),
            size(app.session.byte_limit() as u64)
        )),
        Line::styled(
            format!("{} evicted", app.session.evicted()),
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
    let title = if app.session.filtering() {
        " DISPLAY FILTER · rebuilding… "
    } else {
        " DISPLAY FILTER · proto=tcp port=443 · (a or b) and not c "
    };
    let inner = panel(frame, area, title, color, theme);
    // Saved filters sit left of Apply while the input keeps half the bar.
    let mut reserved = 10;
    let saved: Vec<(usize, String)> = app
        .buttons
        .iter()
        .enumerate()
        .map(|(index, (label, _))| (index, label.clone()))
        .collect();
    for (index, label) in saved {
        let width = label.chars().count() as u16 + 5;
        if reserved + width > inner.width / 2 {
            break;
        }
        reserved += width;
        button(
            frame,
            app,
            Rect::new(
                inner.right().saturating_sub(reserved),
                inner.y,
                width - 1,
                1,
            ),
            &label,
            Action::SavedFilter(index),
            true,
        );
    }
    let input_area = Rect::new(
        inner.x,
        inner.y,
        inner.width.saturating_sub(reserved),
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

/// Keys for the open Stats tab, the most specific first.
fn stats_hint(app: &App) -> &'static str {
    match app.stats.as_ref().map(|d| d.tab) {
        Some(Tab::Overview) | None => {
            " Enter open row · Tab / 1-5 section · u unit · r update now · f full report · S inspect"
        }
        Some(Tab::Ips) => {
            " Enter conversations · p packets · u unit · d direction · Tab section · r update now · S inspect"
        }
        Some(Tab::Conversations) => {
            " Enter stream packets · p address packets · x all · ← back · Tab section · r update now · S inspect"
        }
        Some(Tab::Protocols) => {
            " Enter packets · u unit · Tab / 1-5 section · r update now · f full report · S inspect"
        }
        Some(Tab::Issues) => {
            " Enter first packet · p all packets · Tab / 1-5 section · r update now · S inspect"
        }
    }
}

/// The screen tabs, then the sections of the screen that is open: the panes
/// of Packets or the tabs of Stats.
fn tabs(frame: &mut Frame, app: &mut App, area: Rect) {
    let theme = app.theme;
    let (current, pane) = (app.screen, app.pane);
    let stats = current == Screen::Stats;
    let open_tab = app.stats.as_ref().map(|d| d.tab);
    let issues: u64 = app
        .stats
        .as_ref()
        .map_or(0, |d| d.stats.events.iter().map(|(_, count)| count).sum());
    let sections = |compact: bool| -> Vec<(String, Action, bool)> {
        if !stats {
            return [
                (Pane::Packets, "1 Packets"),
                (Pane::Details, "2 Details"),
                (Pane::Bytes, "3 Bytes"),
            ]
            .into_iter()
            .map(|(to, title)| (format!("[ {title} ]"), Action::Focus(to), to == pane))
            .collect();
        }
        Tab::ALL
            .into_iter()
            .enumerate()
            .map(|(index, tab)| {
                let label = if compact {
                    format!("{} {}", index + 1, tab.short())
                } else if tab == Tab::Issues && issues > 0 {
                    format!("[ {} {} · {issues} ]", index + 1, tab.title())
                } else {
                    format!("[ {} {} ]", index + 1, tab.title())
                };
                let action = Action::Dashboard(DashboardCommand::Tab(tab));
                (label, action, open_tab == Some(tab))
            })
            .collect()
    };
    let screens = |compact: bool| {
        [("Inspect", Screen::Packets), ("Stats", Screen::Stats)].map(|(title, screen)| {
            let label = if compact {
                title.to_string()
            } else {
                format!(" {title} ")
            };
            (label, screen)
        })
    };
    let width = |compact: bool| {
        let gap = if compact { 2 } else { 1 };
        let screens: usize = screens(compact).iter().map(|(l, _)| l.len() + 1).sum();
        let sections: usize = sections(compact)
            .iter()
            .map(|(label, _, _)| Line::raw(label.as_str()).width() + gap)
            .sum();
        screens + 2 + sections - gap
    };
    let compact = width(false) > usize::from(area.width);
    let mut x = area.x;
    let mut place = |frame: &mut Frame, app: &mut App, label: String, style, action, gap| {
        let width = (Line::raw(label.as_str()).width() as u16).min(area.right().saturating_sub(x));
        if width > 0 {
            let rect = Rect::new(x, area.y, width, 1);
            frame.render_widget(Paragraph::new(label).style(style), rect);
            if let Some(action) = action {
                app.regions.buttons.push((rect, action));
            }
        }
        x = x.saturating_add(width + gap);
    };
    for (label, screen) in screens(compact) {
        let style = if screen == current {
            bold(theme.bg).bg(theme.cyan)
        } else {
            bold(theme.muted).bg(theme.panel)
        };
        place(frame, app, label, style, Some(Action::Screen(screen)), 1);
    }
    place(
        frame,
        app,
        "│".into(),
        Style::default().fg(theme.muted),
        None,
        1,
    );
    for (label, action, active) in sections(compact) {
        let color = if active { theme.cyan } else { theme.muted };
        place(
            frame,
            app,
            label,
            bold(color),
            Some(action),
            if compact { 2 } else { 1 },
        );
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
pub(super) use crate::stats::size;

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
