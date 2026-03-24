use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::*;

mod scanner;
mod patterns;
mod report;

use scanner::Scanner;

#[derive(Parser)]
#[command(name = "ai-guardian")]
#[command(about = "🛡️  Security scanner for AI-generated code", long_about = None)]
#[command(after_help = "EXAMPLES:\n  \
    ai-guardian scan              # Scan current directory\n  \
    ai-guardian scan ./src        # Scan specific directory\n  \
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
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { path, json, verbose } => {
            if !json {
                println!("{}", "🛡️  AI Code Guardian - Security Scan".cyan().bold());
                println!();
                println!("Scanning: {}", path.yellow());
                println!();
            }

            let scanner = Scanner::new(&path)?;
            let report = scanner.scan(verbose)?;

            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                report.print();
            }

            // Exit with error code if high-risk issues found
            if report.has_high_risk_issues() {
                std::process::exit(1);
            }
        }
    }

    Ok(())
}
