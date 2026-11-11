// SPDX-License-Identifier: EPL-2.0
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn esc(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\textbackslash{}"),
            '&' => out.push_str("\\&"),
            '%' => out.push_str("\\%"),
            '_' => out.push_str("\\_"),
            '#' => out.push_str("\\#"),
            '$' => out.push_str("\\$"),
            '{' => out.push_str("\\{"),
            '}' => out.push_str("\\}"),
            _ => out.push(c),
        }
    }
    out
}
fn prose(s: &str) -> String {
    s.replace("**", "")
        .split('`')
        .enumerate()
        .map(|(i, s)| {
            if i % 2 == 0 {
                esc(s)
            } else {
                format!("\\path|{s}|")
            }
        })
        .collect()
}
fn markdown(text: &str) -> String {
    let mut out = String::new();
    let mut code = false;
    let mut table = false;
    let mut list = false;
    for line in text.lines() {
        if line.starts_with("```") {
            if list {
                out.push_str("\\end{itemize}\n");
                list = false
            }
            if table {
                out.push_str("\\bottomrule\\end{longtable}\n");
                table = false
            }
            out.push_str(if code{"\\end{lstlisting}\n"}else{"\\begin{lstlisting}[basicstyle=\\ttfamily\\small,breaklines=true,columns=fullflexible]\n"});
            code = !code;
            continue;
        }
        if code {
            out.push_str(line);
            out.push('\n');
            continue;
        }
        if line.starts_with('|') {
            let cells = line
                .trim_matches('|')
                .split('|')
                .map(str::trim)
                .collect::<Vec<_>>();
            if cells
                .iter()
                .all(|c| c.chars().all(|c| c == '-' || c == ':' || c == ' '))
            {
                continue;
            }
            if list {
                out.push_str("\\end{itemize}\n");
                list = false
            }
            if !table {
                let widths = if cells.len() == 2 {
                    vec![0.28, 0.64]
                } else {
                    vec![0.12, 0.46, 0.34]
                };
                out.push_str("\\begin{longtable}{");
                for width in widths {
                    out.push_str(&format!("p{{{width:.2}\\textwidth}}"))
                }
                out.push_str("}\\toprule\n");
                table = true;
                out.push_str(
                    &cells
                        .iter()
                        .map(|c| prose(c))
                        .collect::<Vec<_>>()
                        .join(" & "),
                );
                out.push_str("\\\\\\midrule\\endhead\n");
                continue;
            }
            out.push_str(
                &cells
                    .iter()
                    .map(|c| prose(c))
                    .collect::<Vec<_>>()
                    .join(" & "),
            );
            out.push_str("\\\\\n");
            continue;
        }
        if table {
            out.push_str("\\bottomrule\\end{longtable}\n");
            table = false
        }
        if let Some(item) = line.strip_prefix("- ") {
            if !list {
                out.push_str("\\begin{itemize}\n");
                list = true
            }
            out.push_str("\\item ");
            out.push_str(&prose(item));
            out.push('\n');
            continue;
        }
        if list {
            out.push_str("\\end{itemize}\n");
            list = false
        }
        if let Some(title) = line.strip_prefix("## ") {
            if matches!(title, "Configuration" | "Session and access") {
                out.push_str("\\clearpage\n")
            }
            out.push_str(&format!("\\subsection{{{}}}\n", esc(title)))
        } else if let Some(title) = line.strip_prefix("# ") {
            out.push_str(&format!("\\section{{{}}}\n", esc(title)))
        } else if line.trim().is_empty() {
            out.push_str("\\par\n")
        } else if line
            .split_once(". ")
            .is_some_and(|(n, _)| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        {
            out.push_str(&prose(line));
            out.push_str("\\par\\medskip\n");
        } else {
            out.push_str(&prose(line));
            out.push('\n')
        }
    }
    if list {
        out.push_str("\\end{itemize}\n")
    }
    if table {
        out.push_str("\\bottomrule\\end{longtable}\n")
    }
    out
}
fn preamble(title: &str, kind: &str, version: &str) -> String {
    format!(
        r"\documentclass[a4paper]{{arrowhead}}
\usepackage[T1]{{fontenc}}
\usepackage{{longtable,booktabs,xurl,enumitem}}
\setlength{{\emergencystretch}}{{3em}}
\setlength{{\parindent}}{{0pt}}\setlength{{\parskip}}{{5pt}}
\clubpenalty=10000\widowpenalty=10000
\setlist{{nosep,leftmargin=*}}
\begin{{document}}
\ArrowheadTitle{{{}}}\ArrowheadType{{{kind}}}\ArrowheadTypeShort{{Rust}}
\ArrowheadVersion{{{version}}}\ArrowheadDate{{2026-10-17}}
\ArrowheadAuthor{{Eclipse Arrowhead migration project}}\ArrowheadStatus{{DEVELOPMENT}}
\ArrowheadContact{{Project maintainers}}\ArrowheadFooter{{Eclipse Arrowhead -- Rust LocalCloudManager -- EPL-2.0}}
\ArrowheadSetup
",
        esc(title)
    )
}
fn write(path: impl AsRef<Path>, text: &str) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?
    }
    fs::write(path, text)?;
    Ok(())
}
fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn hashes(root: &Path) -> Result<BTreeMap<String, String>> {
    fn visit(root: &Path, dir: &Path, out: &mut BTreeMap<String, String>) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                if !matches!(
                    entry.file_name().to_str(),
                    Some("target" | ".git" | "docs" | "output")
                ) {
                    visit(root, &path, out)?
                }
            } else if path
                .extension()
                .is_some_and(|e| e == "rs" || e == "html" || e == "css" || e == "js")
                || matches!(
                    entry.file_name().to_str(),
                    Some("Cargo.toml" | "Cargo.lock")
                )
            {
                out.insert(
                    path.strip_prefix(root)?.to_string_lossy().to_string(),
                    digest(&fs::read(path)?),
                );
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    visit(root, root, &mut out)?;
    Ok(out)
}
fn run() -> Result<()> {
    let reference = PathBuf::from(
        std::env::args()
            .nth(1)
            .unwrap_or_else(|| "../../Arrowhead/Arrowhead-test-cloud-rust/core-systems".into()),
    );
    let output =
        PathBuf::from("../ah5-support-runtime-rust/documentation/LocalCloudManager/v5.2.2");
    let compatibility = markdown(&fs::read_to_string("COMPATIBILITY.md")?);
    let references = "\\section{References and qualification}\nSee \\path|docs/source-manifest.json| for original/relocated source SHA256 records, \\path|VERIFICATION.md| for checks actually run, and \\path|docs/LocalCloudManager.sysml| for the descriptive, unparsed variability model. No Java interchangeability, native TLS or sysMonitor publisher is claimed. Existing cloud source and running deployment remain unchanged.\n";
    let documents = [
        ("SysD", "System Description", "5.2.2", "README.md"),
        (
            "SysDD",
            "System Design Description",
            "5.2.2",
            "docs/DESIGN.md",
        ),
        (
            "localCloudManagement-SD",
            "Service Description",
            "1.0.0",
            "docs/localCloudManagement-SD.md",
        ),
        (
            "localCloudManagement-HTTP-IDD",
            "Interface Design Description",
            "1.0.0",
            "docs/HTTP-IDD.md",
        ),
        (
            "monitor-SD",
            "Service Description",
            "1.0.0",
            "docs/monitor-SD.md",
        ),
        (
            "monitor-HTTP-IDD",
            "Interface Design Description",
            "1.0.0",
            "docs/monitor-HTTP-IDD.md",
        ),
    ];
    let mut master = preamble(
        "LocalCloudManager in Rust",
        "System, Service and Interface Catalogue",
        "5.2.2",
    );
    master.push_str("\\addtocontents{toc}{\\protect\\setcounter{tocdepth}{1}}\n\\begin{center}\\vspace*{8mm}{\\LARGE LocalCloudManager in Rust}\\par\\vspace{4mm}{\\large Source relocation and actual interface catalogue}\\end{center}\n\\begin{abstract}Standalone relocated Rust source, dependencies and embedded UI with Arrowhead design/service/interface documents. This is a development HTTP adapter, not the parent support runtime's native mutual-TLS profile. Source relocation does not establish Java interchangeability or a secure cloud deployment.\\end{abstract}\n\\ArrowheadBox{Critical qualification boundary.}{No native listener TLS, certificate-bound provider authentication or sysMonitor AMQP publisher is implemented. Subscription writes are acknowledgements only. Default standalone binding is loopback. Existing cloud deployment is unchanged.}\n\\clearpage\\tableofcontents\\clearpage\n");
    for (name, kind, version, input) in documents {
        let body = markdown(&fs::read_to_string(input)?);
        let mut doc = preamble(&format!("LocalCloudManager / {name}"), kind, version);
        doc.push_str(&body);
        if name == "SysD" || name == "SysDD" {
            doc.push_str("\\clearpage\n");
            doc.push_str(&compatibility)
        }
        doc.push_str(references);
        doc.push_str("\\end{document}\n");
        write(
            output.join(format!("LocalCloudManager-Rust-v5.2.2-{name}.tex")),
            &doc,
        )?;
        master.push_str(&body);
        if name != "monitor-SD" {
            master.push_str("\\clearpage\n")
        }
    }
    master.push_str(&compatibility);
    master.push_str(references);
    master.push_str("\\end{document}\n");
    write(output.join("LocalCloudManager-Rust-Catalogue.tex"), &master)?;
    let mut before = hashes(&reference)?;
    for name in ["LocalCloudManager.md", "LocalCloudManager.sysml"] {
        let path = reference
            .parent()
            .unwrap_or(Path::new("."))
            .join("docs")
            .join(name);
        if path.exists() {
            before.insert(format!("../docs/{name}"), digest(&fs::read(path)?));
        }
    }
    let after = hashes(Path::new("."))?;
    write(
        "docs/source-manifest.json",
        &(serde_json::to_string_pretty(
            &json!({"referenceRoot":reference,"referenceSHA256":before,"relocatedSHA256":after,"notice":"Canonical relocation; original deployment copy retained unchanged. HTTP/legacy identity profile, not native TLS or AMQP telemetry.","services":["localCloudManagement","monitor"],"interface":"generic_http","policy":"NONE"}),
        )? + "\n"),
    )?;
    println!(
        "Generated SysD, SysDD, two SDs, two HTTP IDDs and combined Arrowhead catalogue; source hashes recorded"
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1)
    }
}
