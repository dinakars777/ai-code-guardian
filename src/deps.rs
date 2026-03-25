use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub summary: String,
    pub severity: Option<String>,
    pub references: Vec<Reference>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Reference {
    pub url: String,
}

#[derive(Debug)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct OsvQuery {
    package: OsvPackage,
    version: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<OsvVulnerability>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OsvVulnerability {
    id: String,
    summary: Option<String>,
    database_specific: Option<HashMap<String, serde_json::Value>>,
    references: Option<Vec<OsvReference>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OsvReference {
    url: String,
}

pub fn parse_dependencies(file_path: &Path) -> Result<Vec<Dependency>> {
    let filename = file_path.file_name()
        .and_then(|n| n.to_str())
        .context("Invalid filename")?;

    if filename == "package.json" {
        parse_package_json(file_path)
    } else if filename == "Cargo.toml" {
        parse_cargo_toml(file_path)
    } else if filename == "pyproject.toml" {
        parse_pyproject_toml(file_path)
    } else if filename.ends_with(".txt") || filename.contains("requirements") {
        // Handle requirements.txt, requirements-dev.txt, test-requirements.txt, etc.
        parse_requirements_txt(file_path)
    } else {
        anyhow::bail!("Unsupported dependency file: {}", filename)
    }
}

fn parse_requirements_txt(file_path: &Path) -> Result<Vec<Dependency>> {
    let content = fs::read_to_string(file_path)?;
    let mut deps = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Parse lines like: package==1.2.3 or package>=1.2.3
        if let Some((name, version)) = parse_requirement_line(line) {
            deps.push(Dependency {
                name: name.to_string(),
                version: version.to_string(),
                ecosystem: "PyPI".to_string(),
            });
        }
    }

    Ok(deps)
}

fn parse_requirement_line(line: &str) -> Option<(&str, &str)> {
    // Handle ==, >=, <=, ~=, etc.
    for op in &["==", ">=", "<=", "~=", "!="] {
        if let Some(pos) = line.find(op) {
            let name = line[..pos].trim();
            let version = line[pos + op.len()..].trim()
                .split(',').next()? // Handle multiple constraints
                .trim();
            return Some((name, version));
        }
    }
    None
}

fn parse_package_json(file_path: &Path) -> Result<Vec<Dependency>> {
    let content = fs::read_to_string(file_path)?;
    let json: serde_json::Value = serde_json::from_str(&content)?;
    let mut deps = Vec::new();

    if let Some(dependencies) = json.get("dependencies").and_then(|d| d.as_object()) {
        for (name, version) in dependencies {
            if let Some(ver) = version.as_str() {
                let clean_ver = ver.trim_start_matches('^').trim_start_matches('~');
                deps.push(Dependency {
                    name: name.clone(),
                    version: clean_ver.to_string(),
                    ecosystem: "npm".to_string(),
                });
            }
        }
    }

    Ok(deps)
}

fn parse_cargo_toml(file_path: &Path) -> Result<Vec<Dependency>> {
    let content = fs::read_to_string(file_path)?;
    let toml: toml::Value = toml::from_str(&content)?;
    let mut deps = Vec::new();

    if let Some(dependencies) = toml.get("dependencies").and_then(|d| d.as_table()) {
        for (name, value) in dependencies {
            let version = match value {
                toml::Value::String(v) => v.clone(),
                toml::Value::Table(t) => {
                    if let Some(v) = t.get("version").and_then(|v| v.as_str()) {
                        v.to_string()
                    } else {
                        continue;
                    }
                }
                _ => continue,
            };

            deps.push(Dependency {
                name: name.clone(),
                version,
                ecosystem: "crates.io".to_string(),
            });
        }
    }

    Ok(deps)
}

fn parse_pyproject_toml(file_path: &Path) -> Result<Vec<Dependency>> {
    let content = fs::read_to_string(file_path)?;
    let toml: toml::Value = toml::from_str(&content)?;
    let mut deps = Vec::new();

    // Check [project.dependencies]
    if let Some(dependencies) = toml
        .get("project")
        .and_then(|p| p.get("dependencies"))
        .and_then(|d| d.as_array())
    {
        for dep in dependencies {
            if let Some(dep_str) = dep.as_str() {
                if let Some((name, version)) = parse_requirement_line(dep_str) {
                    deps.push(Dependency {
                        name: name.to_string(),
                        version: version.to_string(),
                        ecosystem: "PyPI".to_string(),
                    });
                }
            }
        }
    }

    Ok(deps)
}

pub async fn check_vulnerability(client: &reqwest::Client, dep: &Dependency) -> Result<Vec<Vulnerability>> {
    let query = OsvQuery {
        package: OsvPackage {
            name: dep.name.clone(),
            ecosystem: dep.ecosystem.clone(),
        },
        version: dep.version.clone(),
    };

    let response = client
        .post("https://api.osv.dev/v1/query")
        .json(&query)
        .send()
        .await?;

    if !response.status().is_success() {
        return Ok(Vec::new());
    }

    let osv_response: OsvResponse = response.json().await?;
    
    let vulnerabilities = osv_response
        .vulns
        .into_iter()
        .map(|v| {
            let severity = v.database_specific
                .as_ref()
                .and_then(|db| db.get("severity"))
                .and_then(|s| s.as_str())
                .map(|s| s.to_string());

            let references = v.references
                .unwrap_or_default()
                .into_iter()
                .map(|r| Reference { url: r.url })
                .collect();

            Vulnerability {
                id: v.id,
                summary: v.summary.unwrap_or_else(|| "No description available".to_string()),
                severity,
                references,
            }
        })
        .collect();

    Ok(vulnerabilities)
}
