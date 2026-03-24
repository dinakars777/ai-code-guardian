use anyhow::Result;
use colored::*;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::mpsc::channel;
use std::time::Duration;

use crate::scanner::Scanner;

pub fn watch_directory(path: &str, verbose: bool) -> Result<()> {
    println!("{}", "🛡️  AI Code Guardian - Watch Mode".cyan().bold());
    println!();
    println!("Watching: {}", path.yellow());
    println!("Press Ctrl+C to stop");
    println!();

    // Initial scan
    println!("{}", "Running initial scan...".dimmed());
    run_scan(path, verbose)?;

    // Setup file watcher
    let (tx, rx) = channel();
    let mut watcher: RecommendedWatcher = Watcher::new(tx, Config::default())?;
    watcher.watch(Path::new(path), RecursiveMode::Recursive)?;

    println!();
    println!("{}", "👀 Watching for changes...".green());
    println!();

    loop {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(Ok(event)) => {
                if should_scan(&event) {
                    println!();
                    println!("{}", "📝 File changed, rescanning...".yellow());
                    println!();
                    if let Err(e) = run_scan(path, verbose) {
                        eprintln!("{}: {}", "Error".red(), e);
                    }
                    println!();
                    println!("{}", "👀 Watching for changes...".green());
                    println!();
                }
            }
            Ok(Err(e)) => eprintln!("{}: {:?}", "Watch error".red(), e),
            Err(_) => {} // Timeout, continue
        }
    }
}

fn should_scan(event: &Event) -> bool {
    // Only scan on modify and create events
    matches!(
        event.kind,
        EventKind::Modify(_) | EventKind::Create(_)
    ) && event.paths.iter().any(|p| {
        if let Some(ext) = p.extension() {
            let ext = ext.to_string_lossy().to_lowercase();
            matches!(
                ext.as_str(),
                "rs" | "js" | "ts" | "jsx" | "tsx" | "py" | "go" | "java" | "c" | "cpp" | "h"
                    | "hpp" | "cs" | "php" | "rb" | "swift" | "kt" | "scala" | "sh" | "bash"
                    | "env" | "yml" | "yaml" | "json" | "toml" | "sql"
            )
        } else {
            false
        }
    })
}

fn run_scan(path: &str, verbose: bool) -> Result<()> {
    let scanner = Scanner::new(path)?;
    let report = scanner.scan(verbose)?;
    report.print();
    Ok(())
}
