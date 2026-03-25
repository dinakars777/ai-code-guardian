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
mod ignore;
mod deps;

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

    /// Check dependencies for known vulnerabilities
    CheckDeps {
        /// Path to dependency file (requirements.txt, package.json, Cargo.toml, pyproject.toml)
        path: String,

        /// Output results as JSON
        #[arg(short, long)]
        json: bool,
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
                tui::run_tui(report)?;
                // Exit code is handled inside run_tui based on real issues
            } else if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
                if report.has_high_risk_issues() {
                    std::process::exit(1);
                }
            } else {
                println!("{}", "🛡️  AI Code Guardian - Security Scan".cyan().bold());
                println!();
                println!("Scanning: {}", path.yellow());
                println!();
                report.print();
                if report.has_high_risk_issues() {
                    std::process::exit(1);
                }
            }
        }
        Commands::Watch { path, verbose } => {
            watch::watch_directory(&path, verbose)?;
        }
        Commands::CheckDeps { path, json } => {
            tokio::runtime::Runtime::new()?.block_on(async {
                check_dependencies(&path, json).await
            })?;
        }
    }

    Ok(())
}

async fn check_dependencies(file_path: &str, json_output: bool) -> Result<()> {
    use std::path::Path;
    
    let path = Path::new(file_path);
    
    if !path.exists() {
        anyhow::bail!("File not found: {}", file_path);
    }

    if !json_output {
        println!("{}", "🛡️  AI Code Guardian - Dependency Check".cyan().bold());
        println!();
        println!("Checking: {}", file_path.yellow());
        println!();
    }

    let dependencies = deps::parse_dependencies(path)?;
    
    if dependencies.is_empty() {
        println!("No dependencies found");
        return Ok(());
    }

    if !json_output {
        println!("Found {} dependencies, checking for vulnerabilities...", dependencies.len());
        println!();
    }

    let mut total_vulns = 0;
    let mut results = Vec::new();
    let client = reqwest::Client::new();

    for dep in &dependencies {
        let vulns = deps::check_vulnerability(&client, dep).await?;
        
        if !vulns.is_empty() {
            total_vulns += vulns.len();
            
            if json_output {
                results.push(serde_json::json!({
                    "package": &dep.name,
                    "version": &dep.version,
                    "ecosystem": &dep.ecosystem,
                    "vulnerabilities": vulns,
                }));
            } else {
                for vuln in &vulns {
                    let severity_str = vuln.severity.as_deref().unwrap_or("UNKNOWN");
                    let severity_colored = match severity_str {
                        "CRITICAL" | "HIGH" => severity_str.red().bold(),
                        "MEDIUM" | "MODERATE" => severity_str.yellow().bold(),
                        _ => severity_str.blue().bold(),
                    };

                    println!("❌ {}: {}", severity_colored, vuln.id.red().bold());
                    println!("   Package: {}@{} ({})", dep.name.cyan(), dep.version, dep.ecosystem);
                    println!("   Summary: {}", vuln.summary);
                    
                    if !vuln.references.is_empty() {
                        println!("   References:");
                        for reference in &vuln.references {
                            println!("     - {}", reference.url.blue());
                        }
                    }
                    println!();
                }
            }
        }
    }

    if json_output {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "total_dependencies": dependencies.len(),
            "vulnerable_packages": results.len(),
            "total_vulnerabilities": total_vulns,
            "results": results,
        }))?);
    } else {
        if total_vulns == 0 {
            println!("{}", "✅ No known vulnerabilities found!".green().bold());
        } else {
            println!("{}", format!("Found {} vulnerabilities in {} packages", total_vulns, results.len()).red().bold());
            std::process::exit(1);
        }
    }

    Ok(())
}
