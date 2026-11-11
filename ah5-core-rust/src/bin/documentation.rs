// SPDX-License-Identifier: EPL-2.0
use arrowhead_core_rust::{config::ROLES, contracts, digest};
use regex::Regex;
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;
fn java_files(root: &Path, out: &mut Vec<PathBuf>) -> AnyResult<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            if !matches!(
                entry.file_name().to_str(),
                Some("target" | ".git" | "output" | "tmp")
            ) {
                java_files(&path, out)?;
            }
        } else if path.extension().is_some_and(|s| s == "java") {
            out.push(path)
        }
    }
    Ok(())
}
fn evaluate(expr: &str, values: &BTreeMap<String, String>, namespace: &str) -> Option<String> {
    let parts = expr.split(" + ");
    let mut out = String::new();
    for part in parts {
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
        .to_string()
}
fn esc(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars() {
        out.push_str(match c {
            '&' => "\\&",
            '%' => "\\%",
            '_' => "\\_",
            '#' => "\\#",
            '$' => "\\$",
            '{' => "\\{",
            '}' => "\\}",
            '\\' => "\\textbackslash{}",
            _ => {
                out.push(c);
                continue;
            }
        })
    }
    out
}
fn preamble(title: &str, kind: &str, short: &str) -> String {
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
\ArrowheadTypeShort{{{short}}}
\ArrowheadVersion{{5.2.2}}
\ArrowheadDate{{2026-10-16}}
\ArrowheadAuthor{{Implementation working draft}}
\ArrowheadStatus{{DEVELOPMENT}}
\ArrowheadContact{{Repository maintainers}}
\ArrowheadFooter{{Eclipse Arrowhead -- native Rust core implementations}}
\ArrowheadSetup
",
        esc(title)
    )
}
fn limitations(role: &str) -> &'static str {
    match role {
        "serviceregistry" => {
            "Registry records, interface templates, expiry, cascades, authorized discovery and management are implemented. Java SQL import, the full property-validator catalogue, normalization, advanced version/time/address matching and all discovery-policy options need additional work. Unsupported custom validators fail explicitly; they are not silently accepted."
        }
        "authentication" => {
            "PASSWORD identities use bcrypt and single active opaque sessions. Java SQL/session import, complete query/time normalization and alternative framework transports require further work. No stored plaintext password or raw identity token is used."
        }
        "consumer-authorization" => {
            "Management-over-provider policy precedence, scoped policies, metadata checks, usage/time-limited tokens, Base64 and RSA JWT tokens, AES wire encryption and authenticated key wrapping are implemented. Foreign-consumer/federation token generation, Java database import, complete DTO/error parity and broad cryptographic interoperability fixtures remain incomplete. AES ECB/CBC are legacy Java wire formats, not recommendations for new protocols."
        }
        "serviceorchestration-dynamic" => {
            "Local/inter-cloud orchestration, authorization, operation filtering, tokens, preferences, matchmaking, locks, history and HTTPS push are implemented. The local PDE extension adds atomic persistent plant scopes and ranked providers; managed scopes cannot escape through inter-cloud flags. Translation bridges, QoS sort/filter and the provider blacklist filter follow the Java LocalServiceOrchestration behind translationEnabled, qosEnabled and blacklistFilter; registry-event-driven reevaluation and full Java parity remain unqualified."
        }
        _ => {
            "Stored candidate priority selection, preferred providers, matchmaking, history, subscriptions and explicit HTTPS push jobs are implemented. Store results intentionally retain Java's sparse result shape. Full Java query/priority-normalization semantics, event-driven reevaluation, MQTT callbacks and Java state import are not ported. Unsupported simple-store criteria are reported as ignored warnings."
        }
    }
}
fn overview(role: &str, name: &str) -> String {
    let mut out = format!(
        "\\section{{{}}}\n\\subsection{{System overview}}\nNative Rust implementation of the local Java module \\path{{{role}/}}. Each named executable checks its configured role and owns an independent identity, listen port and state file. Shared Rust modules implement the runtime; no Java, Python or Go process implements the service.\n\\subsection{{Produced and consumed services}}\nProduced HTTPS definitions: ",
        esc(name)
    );
    for (i, service) in contracts::services(role).iter().enumerate() {
        if i > 0 {
            out.push_str(", \\allowbreak ")
        }
        out.push_str(&format!("\\path{{{}}}", service.definition))
    }
    out.push_str(". Service versions are 1.0.0; the target system version is 5.2.2. Authorities consumed as applicable are Authentication, ServiceRegistry and ConsumerAuthorization. Explicit pinned HTTPS origins and valid cloud identities must be provisioned.\n\\subsection{Architecture and persistent state}\nThe listener uses Tokio, Hyper/Axum and rustls with mandatory client certificates. Verified peer identity is supplied through a private request extension, never a declared-identity header. Business modules share locked JSON state with clone/validate/fsync/rename transactions. Credentials and keys are separate owner-only files. Cross-system operations and callbacks are not distributed transactions.\n\\subsection{Security}\nLocal cloud CN/profile, certificate chain and validity are verified. Identity tokens are checked against Authentication and bound to the client certificate. Management requires a verified sysop or explicit broad whitelist. Outbound peer chain/SAN and expected system CN/profile are checked before credentials are sent. Optional PEM CRLs are enforced at startup-configured trust boundaries and require process restart to reload. No plaintext HTTP listener, TLS bypass or declared SYSTEM identity mode is provided.\n\\subsection{Implementation status and delimitations}\nThis is a development profile, not a certified interchangeable Java replacement. HTTP route presence is not semantic equivalence. Java database migration, MQTT application APIs and production qualification remain outstanding.\n");
    out.push_str(&esc(limitations(role)));
    out.push('\n');
    out
}
fn route_table(role: &str) -> String {
    let mut out = String::from(
        "\\subsection{HTTPS interface operations}\nHTTPS uses JSON unless an operation specifies text. Request bodies are limited to 1 MiB; upstream responses to 8 MiB. Identity-token format: \\texttt{Bearer IDENTITY-TOKEN//token}. Certificate-only identity operations still require verified mutual TLS and apply credential/certificate binding.\n\\begin{longtable}{p{0.10\\textwidth}p{0.65\\textwidth}p{0.17\\textwidth}}\\toprule\nMethod & Path & Access\\\\\\midrule\\endhead\n",
    );
    for r in contracts::routes(role) {
        out.push_str(&format!(
            "\\texttt{{{}}} & \\path{{{}}} & {}\\\\\n",
            r.method, r.path, r.access
        ))
    }
    out.push_str("\\bottomrule\\end{longtable}\nErrors contain errorMessage, errorCode, exceptionType, origin and timestamp. Exact validation/error parity and all Java security-policy settings remain release gates. Unknown routes return 404; unavailable authorities fail closed.\n");
    out
}
fn write(path: impl AsRef<Path>, text: &str) -> AnyResult<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?
    }
    fs::write(path, text)?;
    Ok(())
}
fn run() -> AnyResult<()> {
    let args = std::env::args().collect::<Vec<_>>();
    let source = PathBuf::from(
        args.get(1)
            .map(String::as_str)
            .unwrap_or("../ah5-core-java-spring"),
    );
    let common = PathBuf::from(
        args.get(2)
            .map(String::as_str)
            .unwrap_or("../ah5-common-java-spring"),
    );
    let output = PathBuf::from(args.get(3).map(String::as_str).unwrap_or("documentation"));
    let mut files = Vec::new();
    java_files(&source, &mut files)?;
    java_files(&common, &mut files)?;
    files.sort();
    let mut hashes = BTreeMap::new();
    let mut declarations = BTreeMap::new();
    let declaration = Regex::new(r"public static final String\s+(\w+)\s*=\s*([^;]+);")?;
    for file in &files {
        let bytes = fs::read(file)?;
        let text = String::from_utf8_lossy(&bytes);
        hashes.insert(file.to_string_lossy().to_string(), digest(&bytes));
        for c in declaration.captures_iter(&text) {
            declarations.insert(
                format!("{}.{}", file.file_stem().unwrap().to_string_lossy(), &c[1]),
                c[2].to_string(),
            );
        }
    }
    let mut values = BTreeMap::new();
    for _ in 0..30 {
        let old = values.len();
        for (name, expr) in &declarations {
            if let Some(value) = evaluate(expr, &values, name.rsplit_once('.').unwrap().0) {
                values.insert(name.clone(), value);
            }
        }
        if old == values.len() {
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
        "Rust core systems",
        "System Design and Interface Catalogue",
        "SysDD / IDD",
    );
    master.push_str("\\addtocontents{toc}{\\protect\\setcounter{tocdepth}{1}}\n");
    master.push_str("\\begin{center}\\vspace*{8mm}{\\LARGE Arrowhead core systems in Rust}\\par\\vspace{4mm}{\\large Native implementation and interface catalogue}\\end{center}\n\\begin{abstract}Five active core modules in the local Java 5.2.2 reference are implemented as independently running native Rust systems. This catalogue records the delivered design, services, trust boundaries, interfaces and remaining work. It does not certify full Java interchangeability or a modified cloud deployment.\\end{abstract}\n\\ArrowheadBox{Release boundary.}{Do not replace a Java deployment based only on route coverage. Review the compatibility and verification records, close the documented feature gaps, and qualify real-cloud interoperability, state migration and rollback.}\n\\clearpage\\setcounter{tocdepth}{1}\\tableofcontents\\clearpage\n");
    for (role, name, _) in ROLES {
        let port = arrowhead_core_rust::listen::default_port(role)
            .expect("default port of every core role");
        let mut example = json!({"role":role,"name":name,"cloudSuffix":"RustCloud.Company.arrowhead.eu","listen":format!("127.0.0.1:{port}"),"certificate":format!("secrets/{name}.pem"),"privateKey":format!("secrets/{name}.key"),"ca":"secrets/trust.pem","state":format!("state/{role}.json"),"passwordFile":format!("secrets/{name}.password"),"authenticationURL":"https://authentication:8444","registryURL":"https://serviceregistry:8443","authorizationURL":"https://consumerauthorization:8445","register":false,"advertiseAddress":role,"advertisePort":port,"managementWhitelist":[],"discoveryDirectAccess":[],"bootstrapIdentities":[],"upstreams":{}});
        // serde's camelCase spells Url, not URL; examples use the actual strict field names.
        for (from, to) in [
            ("authenticationURL", "authenticationUrl"),
            ("registryURL", "registryUrl"),
            ("authorizationURL", "authorizationUrl"),
        ] {
            example[to] = example[from].take();
            example.as_object_mut().unwrap().remove(from);
        }
        if role == "consumer-authorization" {
            example["tokenSecretFile"] = "secrets/authorization-token-secret.bin".into();
            example["managementWhitelist"] = json!([
                "ServiceRegistry",
                "DynamicServiceOrchestration",
                "SimpleStoreServiceOrchestration"
            ]);
        }
        if role == "serviceregistry" {
            example["discoveryDirectAccess"] = json!([
                "Authentication",
                "ConsumerAuthorization",
                "DynamicServiceOrchestration",
                "SimpleStoreServiceOrchestration"
            ]);
        }
        if role == "authentication" {
            example["bootstrapIdentities"] = json!([{"systemName":"Sysop","passwordFile":"secrets/Sysop.password","sysop":true}]);
        }
        write(
            Path::new("examples").join(format!("{role}.json")),
            &(serde_json::to_string_pretty(&example)? + "\n"),
        )?;
        let routes = contracts::routes(role);
        let mut extracted = Vec::new();
        for file in files.iter().filter(|f| {
            f.starts_with(source.join(role))
                && f.file_name()
                    .is_some_and(|n| n.to_string_lossy().ends_with("API.java"))
        }) {
            let text = fs::read_to_string(file)?;
            let base = if let Some(c) = class.captures(&text) {
                match evaluate(&c[1], &values, "") {
                    Some(v) => v,
                    None => {
                        issues.push(format!("Unresolved class mapping: {}", file.display()));
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
                let present = routes
                    .iter()
                    .any(|r| r.method == method && canon(&r.path) == canon(&path));
                if !present {
                    issues.push(format!("Missing {role}: {method} {path}"))
                }
                total += 1;
                extracted.push(json!({"method":method,"path":path,"source":file.to_string_lossy(),"sourceSHA256":hashes[&file.to_string_lossy().to_string()],"rustRoutePresent":present}));
            }
        }
        systems.push(json!({"role":role,"name":name,"referenceRoutes":extracted,"rustRoutes":routes,"services":contracts::services(role),"limitations":limitations(role)}));
        let body = overview(role, name);
        master.push_str(&body);
        master.push_str("\\clearpage\n");
        master.push_str(&route_table(role));
        master.push_str("\\clearpage\n");
        let dir = output.join(name);
        write(
            dir.join(format!("{name}-SysD.tex")),
            &(preamble(&format!("{name} (Rust)"), "System Description", "SysD")
                + &body
                + "\\section{References}\nHashed local Java sources and extracted routes: \\path{contracts.json}. No upstream release-tag provenance is asserted.\\end{document}\n"),
        )?;
        write(
            dir.join(format!("{name}-SysDD.tex")),
            &(preamble(
                &format!("{name} (Rust)"),
                "System Design Description",
                "SysDD",
            ) + &body
                + "\\section{Implementation structure}\nSee \\path{src/security.rs}, \\path{src/store.rs}, \\path{src/web.rs} and the role-specific module. Transactions clone state and publish only after durable rename. State locking prevents concurrent processes from sharing the same path. A directory-sync failure after rename is an uncertain durable commit, not an automatic rollback. HTTPS push callbacks are at-least-once across crash recovery; downstream effects can require reconciliation.\n"
                + &route_table(role)
                + "\\end{document}\n"),
        )?;
        write(
            dir.join(format!("{name}-HTTPS-IDD.tex")),
            &(preamble(
                &format!("{name} HTTPS / Rust"),
                "Interface Design Description",
                "IDD",
            ) + "\\section{Interface overview}\nMandatory mutual TLS, Arrowhead token/certificate binding, JSON request and response documents. Echo responses, orchestration subscription IDs, authorization public keys and encryption IV responses are text. Certificate-only operations and management are distinguished in the table.\n"
                + &route_table(role)
                + "\\section{Limitations}\n"
                + &esc(limitations(role))
                + "\\end{document}\n"),
        )?;
        for service in contracts::services(role) {
            let mut doc = preamble(
                &format!("{} (Rust)", service.definition),
                "Service Description",
                "SD",
            );
            doc.push_str(&format!("\\section{{Service overview}}\nDefinition: \\path{{{}}}.\\par\nService version: 1.0.0. Produced by: \\path{{{}}}.\\par\nInterface: \\texttt{{generic\\_https}}, policy \\texttt{{CERT\\_AUTH}}; the application additionally enforces identity/management/ownership rules. Base path: \\path{{{}}}.\n\\section{{Operations}}\n\\begin{{longtable}}{{p{{0.32\\textwidth}}p{{0.12\\textwidth}}p{{0.46\\textwidth}}}}\\toprule\nOperation & Method & Relative path\\\\\\midrule\\endhead\n",service.definition,name,service.base_path));
            for (op, r) in &service.operations {
                doc.push_str(&format!(
                    "\\path{{{op}}} & \\texttt{{{}}} & \\path{{{}}}\\\\\n",
                    r["method"].as_str().unwrap(),
                    r["path"].as_str().unwrap()
                ));
            }
            doc.push_str("\\bottomrule\\end{longtable}\n\\section{Important delimitations}\nDevelopment service profile, not complete Java behavioral equivalence. See system SysDD and HTTPS IDD for trust boundaries, DTO reference and restrictions.\n");
            doc.push_str(&esc(limitations(role)));
            doc.push_str("\n\\end{document}\n");
            write(
                dir.join(format!("{name}-{}-SD.tex", service.definition)),
                &doc,
            )?;
        }
    }
    master.push_str("\\section{Verification and release gates}\nThe verification record distinguishes builds, unit and isolated HTTPS tests, source-route coverage and real deployment qualification. Required outstanding work includes Java-versus-Rust golden DTO/error/security fixtures, completion of unsupported integrations, real brokers and federation peers, imported database recovery, backup/restore and rollback. No document declares a production-ready replacement.\n\\end{document}\n");
    write(output.join("Rust-Core-Systems.tex"), &master)?;
    write(
        output.join("contracts.json"),
        &(serde_json::to_string_pretty(
            &json!({"notice":"Route presence is not behavioral equivalence. Local modified source, development implementation, no deployment.","sourceRoot":source,"commonRoot":common,"sourceSHA256":hashes,"systems":systems,"issues":issues}),
        )? + "\n"),
    )?;
    if !issues.is_empty() {
        for issue in &issues {
            eprintln!("{issue}")
        }
        return Err(format!("{} missing/unresolved reference mappings", issues.len()).into());
    }
    println!(
        "Generated Arrowhead LaTeX for 5 core systems; {total} Java HTTP mappings present; zero missing/unresolved mappings."
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1)
    }
}
