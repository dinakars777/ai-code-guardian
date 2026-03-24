use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::*;

mod scanner;
mod patterns;
mod report;
mod tui;
mod watch;
mod custom_rules;
mod git;

use scanner::Scanner;

#[derive(Parser)]
#[command(name = "ai-guardian")]
#[command(about = "🛡️  Security scanner for AI-generated code", long_about = None)]
#[command(after_help = "EXAMPLES:\n  \
    ai-guardian scan              # Scan current directory\n  \
    ai-guardian scan ./src        # Scan specific directory\n  \
    ai-guardian scan --interactive # Interactive TUI mode\n  \
    ai-guardian watch             # Watch for changes\n  \
    ai-guardian scan --json       # Output as JSON")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan directory for security vulnerabilities
    Scan {
        /// Directory to scan (default: current directory)
        #[arg(default_value = ".")]
        path: String,

        /// Output results as JSON
        #[arg(short, long)]
        json: bool,

        /// Show all issues including low severity
        #[arg(short, long)]
        verbose: bool,

        /// Interactive TUI mode
        #[arg(short, long)]
        interactive: bool,

        /// Only scan git changed files
        #[arg(short, long)]
        git: bool,

        /// Only scan git staged files
        #[arg(short, long)]
        staged: bool,
    },
    
    /// Watch directory for changes and scan automatically
    Watch {
        /// Directory to watch (default: current directory)
        #[arg(default_value = ".")]
        path: String,

        /// Show all issues including low severity
        #[arg(short, long)]
        verbose: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { path, json, verbose, interactive, git, staged } => {
            let scanner = if git || staged {
                if !git::is_git_repo(&path) {
                    eprintln!("Error: Not a git repository");
                    std::process::exit(1);
                }
                
                let files = if staged {
                    git::get_staged_files(&path)?
                } else {
                    git::get_changed_files(&path)?
                };

                if files.is_empty() {
                    println!("No changed files to scan");
                    return Ok(());
                }

                Scanner::new_with_files(&path, files)?
            } else {
                Scanner::new(&path)?
            };

            let report = scanner.scan(verbose)?;

            if interactive {
                let has_high_risk = report.has_high_risk_issues();
                tui::run_tui(report)?;
                if has_high_risk {
                    std::process::exit(1);
                }
            } else if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
                if report.has_high_risk_issues() {
                    std::process::exit(1);
                }
            } else {
                if !json {
                    println!("{}", "🛡️  AI Code Guardian - Security Scan".cyan().bold());
                    println!();
                    println!("Scanning: {}", path.yellow());
                    println!();
                }
                report.print();
                if report.has_high_risk_issues() {
                    std::process::exit(1);
                }
            }
        }
        Commands::Watch { path, verbose } => {
            watch::watch_directory(&path, verbose)?;
        }
    }

    Ok(())
}
