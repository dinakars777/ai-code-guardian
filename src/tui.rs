use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame, Terminal,
};
use std::io;

use crate::report::{Issue, Report, Severity};

struct App {
    issues: Vec<Issue>,
    list_state: ListState,
    marked_false_positives: Vec<usize>,
}

impl App {
    fn new(report: Report) -> Self {
        let mut list_state = ListState::default();
        if !report.issues.is_empty() {
            list_state.select(Some(0));
        }

        Self {
            issues: report.issues,
            list_state,
            marked_false_positives: Vec::new(),
        }
    }

    fn next(&mut self) {
        if self.issues.is_empty() {
            return;
        }
        let i = match self.list_state.selected() {
            Some(i) => {
                if i >= self.issues.len() - 1 {
                    i
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.list_state.select(Some(i));
    }

    fn previous(&mut self) {
        if self.issues.is_empty() {
            return;
        }
        let i = match self.list_state.selected() {
            Some(i) => {
                if i == 0 {
                    0
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.list_state.select(Some(i));
    }

    fn toggle_false_positive(&mut self) {
        if let Some(i) = self.list_state.selected() {
            if let Some(pos) = self.marked_false_positives.iter().position(|&x| x == i) {
                self.marked_false_positives.remove(pos);
            } else {
                self.marked_false_positives.push(i);
            }
        }
    }

    fn get_real_issues(&self) -> Vec<&Issue> {
        self.issues
            .iter()
            .enumerate()
            .filter(|(i, _)| !self.marked_false_positives.contains(i))
            .map(|(_, issue)| issue)
            .collect()
    }
}

pub fn run_tui(report: Report) -> Result<()> {
    if report.issues.is_empty() {
        println!("✅ No security issues found!");
        return Ok(());
    }

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(report);
    let res = run_app(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err);
    }

    // Print summary
    let real_issues = app.get_real_issues();
    println!("\n📊 Summary:");
    println!("Total issues: {}", app.issues.len());
    println!("Marked as false positives: {}", app.marked_false_positives.len());
    println!("Real issues: {}", real_issues.len());

    Ok(())
}

fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
) -> Result<()> {
    loop {
        terminal.draw(|f| ui(f, app))?;

        if let Event::Key(key) = event::read()? {
            match key.code {
                KeyCode::Char('q') => return Ok(()),
                KeyCode::Down | KeyCode::Char('j') => app.next(),
                KeyCode::Up | KeyCode::Char('k') => app.previous(),
                KeyCode::Char('f') => app.toggle_false_positive(),
                _ => {}
            }
        }
    }
}

fn ui(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(8),
            Constraint::Length(3),
        ])
        .split(f.size());

    // Header
    let header = Paragraph::new("🛡️  AI Code Guardian - Interactive Mode")
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(header, chunks[0]);

    // Issue list
    let items: Vec<ListItem> = app
        .issues
        .iter()
        .enumerate()
        .map(|(i, issue)| {
            let severity_color = match issue.severity {
                Severity::High => Color::Red,
                Severity::Medium => Color::Yellow,
                Severity::Low => Color::Blue,
            };

            let prefix = if app.marked_false_positives.contains(&i) {
                "✓ "
            } else {
                "  "
            };

            let content = format!(
                "{}{} - {}:{}",
                prefix, issue.title, issue.file, issue.line
            );

            ListItem::new(content).style(Style::default().fg(severity_color))
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Issues"))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        );

    f.render_stateful_widget(list, chunks[1], &mut app.list_state);

    // Details panel
    if let Some(selected) = app.list_state.selected() {
        if let Some(issue) = app.issues.get(selected) {
            let details = vec![
                Line::from(vec![
                    Span::styled("File: ", Style::default().fg(Color::Gray)),
                    Span::raw(format!("{}:{}", issue.file, issue.line)),
                ]),
                Line::from(vec![
                    Span::styled("Code: ", Style::default().fg(Color::Gray)),
                    Span::raw(&issue.code),
                ]),
                Line::from(vec![
                    Span::styled("Risk: ", Style::default().fg(Color::Gray)),
                    Span::raw(&issue.description),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Fix: ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                    Span::styled(
                        issue.fix_suggestion.as_deref().unwrap_or("N/A"),
                        Style::default().fg(Color::Green),
                    ),
                ]),
            ];

            let details_widget = Paragraph::new(details)
                .block(Block::default().borders(Borders::ALL).title("Details"))
                .wrap(Wrap { trim: true });

            f.render_widget(details_widget, chunks[2]);
        }
    }

    // Help
    let help = Paragraph::new("↑/k: Up | ↓/j: Down | f: Mark False Positive | q: Quit")
        .style(Style::default().fg(Color::Gray))
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(help, chunks[3]);
}
