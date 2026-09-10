//! The interactive approval console.
//!
//! Little Snitch for agents: when a rule says `ask`, the request stops here and
//! a human answers it. The bottom pane is a live tail of the audit log, so the
//! operator can see what the agent has been doing while deciding what to allow next.

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use crate::approval::{PendingView, Verdict};
use crate::audit::AuditEvent;
use crate::state::AppState;

const FEED_CAPACITY: usize = 200;
const TICK: Duration = Duration::from_millis(120);

pub fn run(state: Arc<AppState>) -> Result<()> {
    let mut feed_rx = state.audit.subscribe();
    let mut terminal = ratatui::init();
    let result = event_loop(&state, &mut terminal, &mut feed_rx);
    ratatui::restore();
    result
}

fn event_loop(
    state: &Arc<AppState>,
    terminal: &mut ratatui::DefaultTerminal,
    feed_rx: &mut tokio::sync::broadcast::Receiver<AuditEvent>,
) -> Result<()> {
    let mut feed: VecDeque<AuditEvent> = VecDeque::with_capacity(FEED_CAPACITY);
    let mut selected = 0usize;
    let mut list_state = ListState::default();

    loop {
        while let Ok(event) = feed_rx.try_recv() {
            if feed.len() == FEED_CAPACITY {
                feed.pop_front();
            }
            feed.push_back(event);
        }

        let pending = state.broker.list();
        selected = selected.min(pending.len().saturating_sub(1));
        list_state.select((!pending.is_empty()).then_some(selected));

        terminal.draw(|frame| draw(frame, state, &pending, &mut list_state, &feed))?;

        if !event::poll(TICK)? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }

        let target = pending.get(selected).map(|p| p.id.clone());
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return Ok(()),
            KeyCode::Down | KeyCode::Char('j') => {
                if selected + 1 < pending.len() {
                    selected += 1;
                }
            }
            KeyCode::Up | KeyCode::Char('k') => selected = selected.saturating_sub(1),
            KeyCode::Char('a') => decide(state, target, Verdict::Allow, false),
            KeyCode::Char('A') => decide(state, target, Verdict::Allow, true),
            KeyCode::Char('d') => decide(state, target, Verdict::Deny, false),
            KeyCode::Char('D') => decide(state, target, Verdict::Deny, true),
            KeyCode::Char('f') => state.broker.forget_all(),
            _ => {}
        }
    }
}

fn decide(state: &Arc<AppState>, id: Option<String>, verdict: Verdict, remember: bool) {
    if let Some(id) = id {
        state.broker.decide(&id, verdict, remember);
    }
}

pub(crate) fn draw(
    frame: &mut Frame,
    state: &Arc<AppState>,
    pending: &[PendingView],
    list_state: &mut ListState,
    feed: &VecDeque<AuditEvent>,
) {
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Percentage(45),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(frame.area());

    draw_header(frame, areas[0], state, pending.len());

    let middle = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(areas[1]);

    draw_pending(frame, middle[0], pending, list_state);
    draw_detail(frame, middle[1], pending, list_state.selected());
    draw_feed(frame, areas[2], feed);
    draw_footer(frame, areas[3]);
}

fn draw_header(frame: &mut Frame, area: Rect, state: &Arc<AppState>, pending: usize) {
    let pending_style = if pending > 0 {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let line = Line::from(vec![
        Span::styled(
            " mcp-iap ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!("  proxy {}  ", state.config.server.listen)),
        Span::styled(format!("  {pending} waiting  "), pending_style),
        Span::raw(format!(
            "  {} agents · {} upstreams · {} mcp · {} rules · default {} ",
            state.agents.len(),
            state.config.upstreams.len(),
            state.config.mcp_servers.len(),
            state.acl.rule_count(),
            state.acl.default_action(),
        )),
    ]);

    frame.render_widget(
        Paragraph::new(line).block(Block::default().borders(Borders::ALL)),
        area,
    );
}

fn draw_pending(
    frame: &mut Frame,
    area: Rect,
    pending: &[PendingView],
    list_state: &mut ListState,
) {
    let items: Vec<ListItem> = pending
        .iter()
        .map(|view| {
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{:>4}s ", view.waited_ms / 1000),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(
                    format!("{} ", view.agent_name),
                    Style::default().fg(Color::Magenta),
                ),
                Span::raw(view.summary.clone()),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" waiting for you "),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    frame.render_stateful_widget(list, area, list_state);
}

fn draw_detail(frame: &mut Frame, area: Rect, pending: &[PendingView], selected: Option<usize>) {
    let block = Block::default().borders(Borders::ALL).title(" request ");

    let Some(view) = selected.and_then(|index| pending.get(index)) else {
        frame.render_widget(
            Paragraph::new("Nothing is waiting.\n\nRequests matching an `ask` rule appear here.")
                .style(Style::default().fg(Color::DarkGray))
                .block(block),
            area,
        );
        return;
    };

    let lines = vec![
        field("agent", &format!("{} ({})", view.agent_name, view.request.agent)),
        field("kind", view.request.kind.as_str()),
        field("target", &view.request.target),
        field("method", &view.request.method),
        field("path", &view.request.path),
        field("waiting", &format!("{}s", view.waited_ms / 1000)),
        Line::raw(""),
        Line::from(Span::styled(
            "The credential is never shown to the agent — allowing only lets this one call through.",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    frame.render_widget(
        // `trim: false` keeps the right-aligned field labels aligned.
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block),
        area,
    );
}

fn field<'a>(name: &'a str, value: &str) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("{name:>8}  "), Style::default().fg(Color::DarkGray)),
        Span::styled(value.to_string(), Style::default().fg(Color::White)),
    ])
}

fn draw_feed(frame: &mut Frame, area: Rect, feed: &VecDeque<AuditEvent>) {
    let visible = area.height.saturating_sub(2) as usize;
    let items: Vec<ListItem> = feed
        .iter()
        .rev()
        .take(visible)
        .map(|event| {
            let decision = event
                .record
                .decision
                .as_deref()
                .unwrap_or(&event.record.event);
            let colour = if decision.starts_with("allow") {
                Color::Green
            } else if decision.starts_with("deny") || decision.contains("denied") {
                Color::Red
            } else if decision.starts_with("ask") {
                Color::Yellow
            } else {
                Color::DarkGray
            };
            // Just the clock: everything on screen shares a date.
            let time = event.ts.get(11..19).unwrap_or(&event.ts);
            ListItem::new(Line::from(vec![
                Span::styled(format!("{time} "), Style::default().fg(Color::DarkGray)),
                Span::styled(format!("{decision:<22} "), Style::default().fg(colour)),
                Span::raw(format!(
                    "{} {} {} {}",
                    event.record.agent, event.record.target, event.record.method, event.record.path
                )),
                Span::styled(
                    event
                        .record
                        .status
                        .map(|s| format!(" → {s}"))
                        .unwrap_or_default(),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(
                    event
                        .record
                        .rule
                        .as_deref()
                        .map(|rule| format!("  [{rule}]"))
                        .unwrap_or_default(),
                    Style::default().fg(Color::DarkGray),
                ),
            ]))
        })
        .collect();

    frame.render_widget(
        List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" audit log (live) "),
        ),
        area,
    );
}

fn draw_footer(frame: &mut Frame, area: Rect) {
    let keys = [
        ("↑/↓", "move"),
        ("a", "allow"),
        ("A", "allow for session"),
        ("d", "deny"),
        ("D", "deny for session"),
        ("f", "forget"),
        ("q", "quit"),
    ];
    let mut spans = Vec::new();
    for (key, description) in keys {
        spans.push(Span::styled(
            format!(" {key} "),
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::raw(format!(" {description}  ")));
    }
    frame.render_widget(
        Paragraph::new(Line::from(spans)).block(Block::default().borders(Borders::ALL)),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::AccessRequest;
    use crate::config::Config;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn state_for_test(dir: &std::path::Path) -> Arc<AppState> {
        let config: Config = toml::from_str(&format!(
            r#"
[audit]
path = "{}"
stderr = false

[[agents]]
id = "claude-code"
name = "Claude Code"
token_sha256 = "{}"

[[upstreams]]
name = "github"
base_url = "https://api.github.com"

[[acl]]
name = "github-writes-need-a-human"
target = "github"
methods = ["POST"]
action = "ask"
"#,
            dir.join("audit.jsonl").display(),
            crate::identity::token_hash("iap_test"),
        ))
        .unwrap();
        AppState::build(config, false).unwrap()
    }

    /// Renders the console off-screen so the layout is covered by the test suite
    /// rather than only by looking at it.
    #[tokio::test]
    async fn the_console_shows_a_pending_request_and_the_keys_to_answer_it() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_for_test(dir.path());

        let pending = vec![PendingView {
            id: "abc".into(),
            request: AccessRequest::http("claude-code", "github", "POST", "/repos/acme/api/issues"),
            summary: "github POST /repos/acme/api/issues".into(),
            waited_ms: 4_000,
            agent_name: "Claude Code".into(),
        }];

        let mut feed = VecDeque::new();
        feed.push_back(
            state
                .audit
                .write(crate::audit::AuditRecord {
                    kind: "http".into(),
                    event: "request".into(),
                    agent: "claude-code".into(),
                    target: "github".into(),
                    method: "GET".into(),
                    path: "/repos/acme/api".into(),
                    decision: Some("allow".into()),
                    rule: Some("github-reads".into()),
                    status: Some(200),
                    ..Default::default()
                })
                .unwrap(),
        );

        let mut list_state = ListState::default();
        list_state.select(Some(0));

        let mut terminal = Terminal::new(TestBackend::new(110, 26)).unwrap();
        terminal
            .draw(|frame| draw(frame, &state, &pending, &mut list_state, &feed))
            .unwrap();

        let rendered = format!("{}", terminal.backend());
        println!("{rendered}");

        for expected in [
            "mcp-iap",
            "1 waiting",
            "Claude Code",
            "/repos/acme/api/issues",
            "allow for session",
            "audit log (live)",
            "quit",
            "github-reads",
        ] {
            assert!(
                rendered.contains(expected),
                "console did not render `{expected}`:\n{rendered}"
            );
        }
    }

    #[tokio::test]
    async fn an_empty_queue_says_so_rather_than_rendering_a_blank_panel() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_for_test(dir.path());
        let mut list_state = ListState::default();
        let mut terminal = Terminal::new(TestBackend::new(110, 26)).unwrap();
        terminal
            .draw(|frame| draw(frame, &state, &[], &mut list_state, &VecDeque::new()))
            .unwrap();
        let rendered = format!("{}", terminal.backend());
        assert!(rendered.contains("Nothing is waiting"), "{rendered}");
    }
}
