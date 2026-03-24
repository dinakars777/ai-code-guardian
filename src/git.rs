use anyhow::{Context, Result};
use std::process::Command;

pub fn get_changed_files(path: &str) -> Result<Vec<String>> {
    let output = Command::new("git")
        .args(&["diff", "--name-only", "--diff-filter=ACMR"])
        .current_dir(path)
        .output()
        .context("Failed to execute git diff")?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    let files = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|s| s.to_string())
        .collect();

    Ok(files)
}

pub fn get_staged_files(path: &str) -> Result<Vec<String>> {
    let output = Command::new("git")
        .args(&["diff", "--cached", "--name-only", "--diff-filter=ACMR"])
        .current_dir(path)
        .output()
        .context("Failed to execute git diff --cached")?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    let files = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|s| s.to_string())
        .collect();

    Ok(files)
}

pub fn is_git_repo(path: &str) -> bool {
    Command::new("git")
        .args(&["rev-parse", "--git-dir"])
        .current_dir(path)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}
