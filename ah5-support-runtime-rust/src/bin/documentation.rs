// SPDX-License-Identifier: EPL-2.0
use arrowhead_support_rust::{config::ROLES, contracts, digest};
use regex::Regex;
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn java_files(root: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            if !matches!(
                entry.file_name().to_str(),
                Some("target" | ".git" | "output" | "tmp" | "_superseeded")
            ) {
                java_files(&path, out)?
            }
        } else if path.extension().is_some_and(|s| s == "java") {
            out.push(path)
        }
    }
    Ok(())
}
fn evaluate(expr: &str, values: &BTreeMap<String, String>, namespace: &str) -> Option<String> {
    let mut out = String::new();
    for part in expr.split(" + ") {
        let part = part.trim();
        if part.starts_with('"') && part.ends_with('"') {
            out.push_str(&serde_json::from_str::<String>(part).ok()?)
        } else {
            out.push_str(
                values
                    .get(part)
                    .or_else(|| values.get(&format!("{namespace}.{part}")))?,
            )
        }
    }
    Some(out)
}
fn canon(path: &str) -> String {
    Regex::new(r"\{[^}]+\}")
        .unwrap()
        .replace_all(path, "{}")
        .into_owned()
}
fn esc(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars() {
        match c {
            '&' => out.push_str("\\&"),
            '%' => out.push_str("\\%"),
            '_' => out.push_str("\\_"),
            '#' => out.push_str("\\#"),
            '$' => out.push_str("\\$"),
            '{' => out.push_str("\\{"),
            '}' => out.push_str("\\}"),
            '\\' => out.push_str("\\textbackslash{}"),
            _ => out.push(c),
        }
    }
    out
}
fn write(path: impl AsRef<Path>, text: &str) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?
    }
    fs::write(path, text)?;
    Ok(())
}
fn prose(markdown: &str) -> String {
    markdown
        .replace("**", "")
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
fn folder(role: &str, name: &str) -> String {
    match role {
        "aigym" => "AI-gym".into(),
        "choreographer" => "Choreography".into(),
        "certificateauthority" | "sysmonitor" | "gatekeeper" | "gatetunnel" => {
            "JavaSupportRuntime".into()
        }
        _ => name.into(),
    }
}
fn preamble(title: &str, kind: &str) -> String {
    format!(
        r"\documentclass[a4paper]{{arrowhead}}
\usepackage[T1]{{fontenc}}
\usepackage{{longtable,booktabs,xurl}}
\setlength{{\emergencystretch}}{{3em}}
\setlength{{\parindent}}{{0pt}}
\setlength{{\parskip}}{{5pt}}
\begin{{document}}
\ArrowheadTitle{{{}}}
\ArrowheadType{{{kind}}}
\ArrowheadTypeShort{{Rust}}
\ArrowheadVersion{{5.2.2}}
\ArrowheadDate{{2026-10-17}}
\ArrowheadAuthor{{Implementation working draft}}
\ArrowheadStatus{{DEVELOPMENT}}
\ArrowheadContact{{Repository maintainers}}
\ArrowheadFooter{{Eclipse Arrowhead -- Rust support development port}}
\ArrowheadSetup
",
        esc(title)
    )
}
fn details(name: &str, compat: &str) -> String {
    let table = compat
        .lines()
        .find(|l| l.starts_with(&format!("| {name} |")))
        .unwrap_or("");
    let cells = table.split('|').map(str::trim).collect::<Vec<_>>();
    let delivered = cells.get(2).unwrap_or(&"").replace("**", "");
    let gaps = cells.get(3).unwrap_or(&"").replace("**", "");
    format!(
        "\\subsection{{Implemented behavior}}\n{}\n\\subsection{{Open release gates}}\n{}. All systems remain development profiles, not certified interchangeable Java replacements. See \\path{{COMPATIBILITY.md}} for detailed DTO fields and restrictions; the Java sources remain the authoritative contract.\n",
        esc(&delivered),
        esc(&gaps)
    )
}
fn overview(role: &str, name: &str, compat: &str) -> String {
    let folder = folder(role, name);
    let mut body = format!(
        "\\section{{{name}}}\n\\subsection{{System overview}}\nNative Rust development profile for local Java source \\path{{{folder}/}}. One independently configured executable, identity, port and state file per role. No Java, Go or Python process implements the service. Some essential operations are explicitly unavailable.\n\\subsection{{Design and trust boundaries}}\nTokio/Hyper/Axum with rustls enforces mutual TLS. Certificate chain, validity, local CN/profile and startup-configured optional CRLs are checked. Configured CRLs and TLS material reload without process restart; verification fails closed when required material is unavailable. Tokens are verified with Authentication and bound to the TLS identity. Business calls require ConsumerAuthorization; management requires a verified sysop or explicit broad whitelist. CA provisioning instead applies Java-style named certificate-principal rights. Outbound authorities are pinned to expected CN/profile before credentials are sent, in addition to chain, SAN and time validation.\n\\subsection{{Persistent state}}\nIndependent locked atomic JSON replaces SQL. Clone/validate/fsync/rename commits prevent partially published local transactions. Rename is the commit point; directory-sync failure is an uncertain durable commit, not a rollback. Owner-only keys/password files are separate. Network effects are not distributed transactions; interrupted starts and bridge operations require reconciliation. No automatic Java state import, clustering or deployment is delivered.\n"
    );
    body.push_str(&details(name, compat));
    body.push_str(
        "\\subsection{Produced and consumed services}\nAdvertised implemented HTTPS definitions: ",
    );
    for (i, svc) in contracts::services(role).iter().enumerate() {
        if i > 0 {
            body.push_str(", \\allowbreak ")
        }
        body.push_str(&format!("\\path{{{}}}", svc.definition))
    }
    body.push_str(".\\par\nAuthorities consumed as applicable: Authentication, ServiceRegistry, ConsumerAuthorization and explicitly configured pinned adapter/provider origins. Only implemented operations are registered. Service versions are 1.0.0 except Gatekeeper/GateTunnel 5.2.2. Optional native AMQP monitoring publishes echo, power and status observations.\n");
    body
}
fn route_table(role: &str) -> String {
    let mut out = String::from(
        "\\subsection{HTTPS operations}\nJSON unless raw configuration bytes, PEM CRL or echo text. Bodies: 1 MiB; remote responses: 8 MiB. Header: \\texttt{Bearer IDENTITY-TOKEN//token}. Unknown routes return 404, absent dependencies 503. Unported operations return 501 after applicable access checks and are excluded from registration. Route presence is not semantic parity.\n\\begin{longtable}{p{0.09\\textwidth}p{0.59\\textwidth}p{0.20\\textwidth}}\\toprule\nMethod & Path & Access / status\\\\\\midrule\\endhead\n",
    );
    for r in contracts::routes(role) {
        out.push_str(&format!(
            "\\texttt{{{}}} & \\path{{{}}} & {}{}\\\\\n",
            r.method,
            r.path,
            r.access,
            if r.implemented { "" } else { " / 501" }
        ))
    }
    out.push_str("\\bottomrule\\end{longtable}\nError envelope: errorMessage, errorCode, exceptionType, origin and timestamp. Full Java status, DTO and validation equivalence requires differential testing.\n");
    out
}
fn run() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    let source = PathBuf::from(
        args.get(1)
            .map(String::as_str)
            .unwrap_or("../ah5-support-java-spring"),
    );
    let common = PathBuf::from(
        args.get(2)
            .map(String::as_str)
            .unwrap_or("../ah5-common-java-spring"),
    );
    let output = PathBuf::from(args.get(3).map(String::as_str).unwrap_or("documentation"));
    let compat = fs::read_to_string("COMPATIBILITY.md")?;
    let mut files = Vec::new();
    java_files(&source, &mut files)?;
    java_files(&common, &mut files)?;
    files.sort();
    let mut hashes = BTreeMap::new();
    let mut declarations = BTreeMap::new();
    let declaration = Regex::new(r"public static final String\s+(\w+)\s*=\s*([^;]+);")?;
    for file in &files {
        let bytes = fs::read(file)?;
        hashes.insert(file.to_string_lossy().to_string(), digest(&bytes));
        let text = String::from_utf8_lossy(&bytes);
        for c in declaration.captures_iter(&text) {
            declarations.insert(
                format!("{}.{}", file.file_stem().unwrap().to_string_lossy(), &c[1]),
                c[2].to_string(),
            );
        }
    }
    let mut values = BTreeMap::new();
    for _ in 0..30 {
        let before = values.len();
        for (name, expr) in &declarations {
            if let Some(value) = evaluate(expr, &values, name.rsplit_once('.').unwrap().0) {
                values.insert(name.clone(), value);
            }
        }
        if before == values.len() {
            break;
        }
    }
    let class = Regex::new(r"@RequestMapping\((?:path\s*=\s*|value\s*=\s*)?([^,)]+)")?;
    let mapping =
        Regex::new(r"@(Get|Post|Put|Patch|Delete)Mapping\((?:path\s*=\s*|value\s*=\s*)?([^,)]+)")?;
    let mut systems = Vec::new();
    let mut issues = Vec::new();
    let mut total = 0;
    let mut master = preamble(
        "Rust support systems",
        "System Design and Interface Catalogue",
    );
    master.push_str("\\addtocontents{toc}{\\protect\\setcounter{tocdepth}{1}}\n\\begin{center}\\vspace*{6mm}{\\LARGE Arrowhead support systems in Rust}\\par\\vspace{4mm}{\\large Development implementation and interface catalogue}\\end{center}\n\\begin{abstract}Fifteen active support-system profiles from the local modified Java tree have native Rust executables. This catalogue distinguishes implemented behavior, explicit unsupported interfaces and unqualified integrations. It is NOT a claim of complete v5.2.2 Java interchangeability.\\end{abstract}\n\\ArrowheadBox{Do not replace working clouds.}{Onboarding provisioning, federation/tunnel data planes and SysMonitor broker workers are not implemented. Other profiles have documented semantic gaps. No live cloud was changed.}\n\\clearpage\\tableofcontents\\clearpage\n");
    for (role, name, _) in ROLES {
        let port = arrowhead_support_rust::listen::default_port(role)
            .expect("default port of every support role");
        let mut example = json!({"role":role,"name":name,"cloudSuffix":"RustCloud.Company.arrowhead.eu","listen":format!("127.0.0.1:{port}"),"certificate":format!("secrets/{name}.pem"),"privateKey":format!("secrets/{name}.key"),"ca":"secrets/trust.pem","state":format!("state/{role}.json"),"passwordFile":format!("secrets/{name}.password"),"authenticationUrl":"https://authentication:8444/","registryUrl":"https://serviceregistry:8443/","authorizationUrl":"https://consumerauthorization:8445/","register":false,"advertiseAddress":role,"advertisePort":port,"managementWhitelist":[],"upstreams":{}});
        if role == "certificateauthority" {
            example["caCertificate"] = "secrets/cloud-ca.pem".into();
            example["caSigningKey"] = "secrets/cloud-ca.key".into();
        }
        write(
            Path::new("examples").join(format!("{role}.json")),
            &(serde_json::to_string_pretty(&example)? + "\n"),
        )?;
        let routes = contracts::routes(role);
        let source_folder = folder(role, name);
        let mut extracted = Vec::new();
        if source_folder != "JavaSupportRuntime" {
            for file in files.iter().filter(|f| {
                f.starts_with(source.join(&source_folder))
                    && f.file_name().is_some_and(|n| {
                        n.to_string_lossy().ends_with("API.java")
                            || n.to_string_lossy().ends_with("Controller.java")
                    })
            }) {
                let text = fs::read_to_string(file)?;
                let base = if let Some(c) = class.captures(&text) {
                    match evaluate(&c[1], &values, "") {
                        Some(v) => v,
                        None => {
                            issues.push(format!("Unresolved class mapping {}", file.display()));
                            continue;
                        }
                    }
                } else {
                    String::new()
                };
                for c in mapping.captures_iter(&text) {
                    let Some(suffix) = evaluate(&c[2], &values, "") else {
                        issues.push(format!(
                            "Unresolved mapping {} in {}",
                            &c[2],
                            file.display()
                        ));
                        continue;
                    };
                    let method = c[1].to_uppercase();
                    let path = format!("{base}{suffix}");
                    let matched = routes
                        .iter()
                        .find(|r| r.method == method && canon(&r.path) == canon(&path));
                    if matched.is_none() {
                        issues.push(format!("Missing {name}: {method} {path}"))
                    }
                    total += 1;
                    extracted.push(json!({"method":method,"path":path,"source":file.to_string_lossy(),"rustRoutePresent":matched.is_some(),"implemented":matched.is_some_and(|r|r.implemented)}));
                }
            }
        }
        systems.push(json!({"role":role,"name":name,"folder":source_folder,"referenceRoutes":extracted,"referenceMethod":if source_folder=="JavaSupportRuntime"{"manual shared-runtime review; not Spring extraction"}else{"Spring mapping extraction"},"rustRoutes":routes,"services":contracts::services(role)}));
        let body = overview(role, name, &compat);
        master.push_str(&body);
        master.push_str("\\clearpage\n");
        master.push_str(&route_table(role));
        master.push_str("\\clearpage\n");
        let dir = output.join(name);
        for (kind, suffix) in [
            ("System Description", "SysD"),
            ("System Design Description", "SysDD"),
            ("HTTPS Interface Design Description", "HTTPS-IDD"),
        ] {
            let mut doc = preamble(&format!("{name} (Rust)"), kind);
            doc.push_str(&body);
            if suffix != "SysD" {
                doc.push_str(&route_table(role))
            }
            doc.push_str("\\section{References and qualification}\nSee \\path{contracts.json} for local Java SHA256 hashes/mappings, \\path{COMPATIBILITY.md} for DTO details and gaps, and \\path{VERIFICATION.md} for tests actually run. No upstream release-tag provenance, complete replacement or real-cloud interoperability is asserted.\\end{document}\n");
            write(dir.join(format!("{name}-{suffix}.tex")), &doc)?;
        }
        for service in contracts::services(role) {
            let mut doc = preamble(
                &format!("{} (Rust)", service.definition),
                "Service Description",
            );
            doc.push_str(&format!("\\section{{Service overview}}\nDefinition: \\path{{{}}}.\\par\nProducer: \\path{{{name}}}. Version: {}.\\par\nInterface: \\texttt{{generic\\_https}}, policy \\texttt{{CERT\\_AUTH}}. Additional token/management/ownership checks apply. Base: \\path{{{}}}. Only implemented operations are advertised; this does not imply Java parity.\n\\section{{Operations}}\n\\begin{{longtable}}{{p{{0.30\\textwidth}}p{{0.12\\textwidth}}p{{0.48\\textwidth}}}}\\toprule\nOperation & Method & Relative path\\\\\\midrule\\endhead\n",service.definition,if ["gatekeeper","gatetunnel"].contains(&role){"5.2.2"}else{"1.0.0"},service.base_path));
            for (op, r) in &service.operations {
                doc.push_str(&format!(
                    "\\path{{{op}}} & \\texttt{{{}}} & \\path{{{}}}\\\\\n",
                    r["method"].as_str().unwrap(),
                    r["path"].as_str().unwrap()
                ))
            }
            doc.push_str("\\bottomrule\\end{longtable}\n");
            doc.push_str(&details(name, &compat));
            doc.push_str("\n\\end{document}\n");
            write(
                dir.join(format!("{name}-{}-SD.tex", service.definition)),
                &doc,
            )?;
        }
    }
    master.push_str("\\section{Contract details}\n");
    for line in compat.lines().filter_map(|l| l.strip_prefix("- ")) {
        master.push_str(&prose(line));
        master.push_str("\\par\\medskip\n");
    }
    master.push_str("\\clearpage\\section{Release qualification gates}\nComplete unported operations before replacing Java. Add differential Java/Rust DTO, status, normalization and policy fixtures. Qualify AMQPS/MQTT brokers, federation profiles, onboarding, CRL reload, backups, SQL migration, crash recovery and rollback. No live cloud deployment is included.\\end{document}\n");
    write(output.join("Rust-Support-Systems.tex"), &master)?;
    // Preserve exact compatibility details in a standalone Arrowhead-style design annex.
    let mut annex = preamble(
        "Rust support compatibility and contracts",
        "Design compatibility annex",
    );
    for line in compat.lines() {
        if let Some(h) = line.strip_prefix("# ") {
            annex.push_str(&format!("\\section{{{}}}\n", esc(h)))
        } else if let Some(h) = line.strip_prefix("## ") {
            annex.push_str(&format!("\\subsection{{{}}}\n", esc(h)))
        } else if line.starts_with('|') {
            continue;
        } else if !line.is_empty() {
            annex.push_str(&prose(line.trim_start_matches("- ")));
            annex.push_str("\\par\n");
        }
    }
    annex.push_str("\\end{document}\n");
    write(output.join("Compatibility-Annex.tex"), &annex)?;
    write(
        output.join("contracts.json"),
        &(serde_json::to_string_pretty(
            &json!({"notice":"Route presence is not behavior; unported essential services remain; no deployment.","sourceRoot":source,"commonRoot":common,"sourceSHA256":hashes,"systems":systems,"issues":issues}),
        )? + "\n"),
    )?;
    println!(
        "15 profiles; {total} extracted Spring mappings; {} audit issues",
        issues.len()
    );
    for issue in &issues {
        eprintln!("{issue}")
    }
    if !issues.is_empty() {
        return Err("Reference audit has missing/unresolved mappings".into());
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1)
    }
}
