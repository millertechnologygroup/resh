use anyhow::{Context, Result};
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Component, PathBuf};
use tera::{Context as TeraContext, Tera};
use url::Url;

use crate::core::{
    help::{HandleHelp, VerbDetail, VerbHelp},
    registry::{Args, Handle, IoStreams},
    status::Status,
};

/// JSON schema for validation results
#[derive(Debug, Serialize, Deserialize)]
struct ValidationError {
    kind: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    column: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TemplateInfo {
    source: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ValidationResult {
    ok: bool,
    template: TemplateInfo,
    strict: bool,
    errors: Vec<ValidationError>,
    warnings: Vec<ValidationError>,
}

/// JSON schema for render results
#[derive(Debug, Serialize, Deserialize)]
struct ContextInfo {
    keys: Vec<String>,
    raw: Value,
}

#[derive(Debug, Serialize, Deserialize)]
struct BodyInfo {
    #[serde(rename = "type")]
    body_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    base64: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RenderResult {
    ok: bool,
    engine: String,
    template: TemplateInfo,
    context: ContextInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<BodyInfo>,
    errors: Vec<ValidationError>,
}

/// JSON schema for test cases and results
#[derive(Debug, Serialize, Deserialize)]
struct TemplateTestCase {
    name: String,
    context: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    contains: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    not_contains: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TestCaseResult {
    name: String,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    contains: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    not_contains: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rendered: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diff: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TestResult {
    template: String,
    ok: bool,
    total: usize,
    passed: usize,
    failed: usize,
    stop_on_first_fail: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    cases: Vec<TestCaseResult>,
}

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("template", |u| {
        Ok(Box::new(TemplateHandle::from_url(u.clone())?))
    });
}

/// Metadata for `resh template --help` and `resh template <verb> --help`.
static TEMPLATE_HELP: HandleHelp = HandleHelp {
    description: "The template handle renders, validates, and tests text templates with the \
        Tera engine and reports every result as a JSON object. The stage URL names a \
        template file relative to the current directory, such as \
        template://welcome.txt, or uses template://inline with the template \
        text passed as an argument. Template variables come from a JSON context argument \
        or a JSON context file.",
    usage: "resh template://<path>|inline.<verb>[(key=value,...)]",
    verbs: &[
        VerbHelp {
            name: "render",
            definition: "Renders a template with a JSON context and reports the rendered body, \
                the context keys, and template details as a JSON object.",
            detail: Some(VerbDetail {
                usage: "resh template://<path>.render [template=<text>] [from=<text>]\n  \
                    [context=<json>] [context_file=<path>] [format=text|html|json|bytes]\n  \
                    [timeout_ms=<n>]",
                example: "resh --json-pretty template://welcome.txt.render \
                    'context={\"name\":\"alice\"}'",
                example_output: Some(
                    r#"{
  "body": {
    "type": "text",
    "value": "Hello, alice!"
  },
  "context": {
    "keys": [
      "name"
    ],
    "raw": {
      "name": "alice"
    }
  },
  "engine": "tera",
  "errors": [],
  "ok": true,
  "template": {
    "name": "welcome.txt",
    "path": "welcome.txt",
    "size": 18,
    "source": "file"
  }
}

Shown for a file containing "Hello, {{ name }}!" with --json-pretty. The
context argument overrides context_file, format=json parses the rendered
text into body.value, and format=bytes returns body.base64 instead.
timeout_ms stops rendering after that many milliseconds (exit 124); 0, the
default, means no limit."#,
                ),
            }),
        },
        VerbHelp {
            name: "validate",
            definition: "Checks a template for syntax errors and, using an optional JSON \
                context, for render errors such as missing variables.",
            detail: Some(VerbDetail {
                usage: "resh template://<path>.validate [template=<text>] [from=<text>]\n  \
                    [inline=<text>] [context=<json>] [context_file=<path>]\n  \
                    [strict=true|false] [encoding=utf-8] [timeout_ms=<n>]",
                example: "resh --json-pretty template://welcome.txt.validate \
                    'context={\"name\":\"alice\"}'",
                example_output: Some(
                    r#"{
  "errors": [],
  "ok": true,
  "strict": true,
  "template": {
    "name": "welcome.txt",
    "path": "welcome.txt",
    "size": 18,
    "source": "file"
  },
  "warnings": []
}

Shown with --json-pretty. Problems are reported in errors as objects with
kind and message fields, and the command exits with status 1 (2 for an
invalid argument, 124 when timeout_ms passes). With strict=false, missing
variables are reported in warnings instead and the command succeeds."#,
                ),
            }),
        },
        VerbHelp {
            name: "test",
            definition: "Renders a template once per test case and checks each result against \
                the case's expected, contains, and not_contains values.",
            detail: Some(VerbDetail {
                usage: "resh template://<path>.test [template=<text>] [from=<text>]\n  \
                    [cases=<json>] [cases_file=<path>] [stop_on_first_fail=true|false]\n  \
                    [capture_output=none|summary|full] [timeout_ms=<n>]",
                example: "resh --json-pretty template://welcome.txt.test",
                example_output: Some(
                    r#"{
  "cases": [
    {
      "expected": "Hello, alice!",
      "name": "alice",
      "ok": true
    }
  ],
  "failed": 0,
  "ok": true,
  "passed": 1,
  "stop_on_first_fail": false,
  "template": "welcome.txt",
  "total": 1
}

Shown with --json-pretty. Without cases or cases_file, the cases are read
from the file next to the template with the extension .tests.json, here
welcome.tests.json. When timeout_ms passes, the cases that ran are reported
and the command exits 124."#,
                ),
            }),
        },
    ],
};

pub struct TemplateHandle {
    template_path: Option<PathBuf>,
    is_help_request: bool,
    help_verb: Option<String>,
}

fn unescape_backslashes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.peek() {
                Some(' ') => {
                    it.next();
                    out.push(' ');
                }
                Some('\\') => {
                    it.next();
                    out.push('\\');
                }
                Some('t') => {
                    it.next();
                    out.push('\t');
                }
                Some('n') => {
                    it.next();
                    out.push('\n');
                }
                _ => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn normalize_path(p: &PathBuf) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::CurDir => {}
            // `a/..` cancels out, but a leading `..` is kept: dropping it
            // would read a different file than the one named.
            Component::ParentDir => {
                let can_pop = matches!(out.components().next_back(), Some(Component::Normal(_)));
                if can_pop {
                    out.pop();
                } else {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    if out.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        out
    }
}

/// Returns the "Variable ... not found" message if any error in `e`'s
/// source chain reports a missing variable.
fn missing_variable_message(e: &tera::Error) -> Option<String> {
    let mut cur: Option<&dyn std::error::Error> = Some(e);
    while let Some(err) = cur {
        let msg = err.to_string();
        if msg.contains("Variable") && (msg.contains("not found") || msg.contains("doesn't exist"))
        {
            return Some(msg);
        }
        cur = err.source();
    }
    None
}

/// The arguments each verb accepts. Help usage lists exactly these, and
/// anything else is refused (exit 2) before the verb reads or renders.
const RENDER_ARGS: &[&str] = &[
    "template",
    "from",
    "context",
    "context_file",
    "format",
    "timeout_ms",
];
const VALIDATE_ARGS: &[&str] = &[
    "template",
    "from",
    "inline",
    "context",
    "context_file",
    "strict",
    "encoding",
    "timeout_ms",
];
const TEST_ARGS: &[&str] = &[
    "template",
    "from",
    "cases",
    "cases_file",
    "stop_on_first_fail",
    "capture_output",
    "timeout_ms",
];

/// Arguments accepted by `verb`, or `None` for an unknown verb.
fn verb_args(verb: &str) -> Option<&'static [&'static str]> {
    match verb {
        "render" => Some(RENDER_ARGS),
        "validate" => Some(VALIDATE_ARGS),
        "test" => Some(TEST_ARGS),
        _ => None,
    }
}

/// The accepted argument closest to `bad` (edit distance at most 2, or a
/// case-only difference), for a "did you mean" hint.
fn suggest<'a>(bad: &str, allowed: &[&'a str]) -> Option<&'a str> {
    fn distance(a: &str, b: &str) -> usize {
        let b: Vec<char> = b.chars().collect();
        let mut prev: Vec<usize> = (0..=b.len()).collect();
        for (i, ca) in a.chars().enumerate() {
            let mut cur = vec![i + 1];
            for (j, cb) in b.iter().enumerate() {
                let cost = usize::from(ca != *cb);
                cur.push((prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1));
            }
            prev = cur;
        }
        prev[b.len()]
    }
    let lower = bad.to_ascii_lowercase().replace('-', "_");
    allowed
        .iter()
        .map(|a| (distance(&lower, a), *a))
        .filter(|(d, _)| *d <= 2)
        .min_by_key(|(d, _)| *d)
        .map(|(_, a)| a)
}

/// " (did you mean `x`?)" when `bad` looks like a typo of an accepted name.
fn did_you_mean(bad: &str, allowed: &[&str]) -> String {
    suggest(bad, allowed)
        .map(|s| format!(" (did you mean `{s}`?)"))
        .unwrap_or_default()
}

/// No cases were given and the template has no default `.tests.json` file.
#[derive(Debug)]
struct NoCases;

impl std::fmt::Display for NoCases {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("no test cases provided and default tests file not found")
    }
}

impl std::error::Error for NoCases {}

/// Exit code for a verb stopped by `timeout_ms` (as for timeout(1)).
const TIMEOUT_EXIT: i32 = 124;

/// Options parsed and checked before a verb acts.
struct Options {
    /// 0 = no limit.
    timeout_ms: u64,
    strict: bool,
    stop_on_first_fail: bool,
    capture_output: String,
    format: String,
}

fn invalid_argument(message: String) -> ValidationError {
    ValidationError {
        kind: "invalid_argument".to_string(),
        message,
        line: None,
        column: None,
    }
}

fn invalid_format_error(format: &str) -> ValidationError {
    ValidationError {
        kind: "invalid_format".to_string(),
        message: format!(
            "invalid format '{}'. Allowed values: text, html, json, bytes",
            format
        ),
        line: None,
        column: None,
    }
}

/// Tera's message followed by every cause, so a render error names the
/// failing variable or filter instead of only "Failed to render ...".
fn error_chain(e: &tera::Error) -> String {
    let mut parts = vec![e.to_string()];
    let mut cur = std::error::Error::source(e);
    while let Some(err) = cur {
        let msg = err.to_string();
        if !parts.contains(&msg) {
            parts.push(msg);
        }
        cur = err.source();
    }
    parts.join(": ")
}

/// Why rendering did not finish.
#[derive(Debug)]
enum LimitError {
    /// `timeout_ms` passed. The render thread is abandoned; it ends with
    /// the process.
    TimedOut,
    /// The render thread could not start or panicked.
    Failed(String),
}

impl LimitError {
    fn error(&self, timeout_ms: u64) -> ValidationError {
        match self {
            LimitError::TimedOut => ValidationError {
                kind: "timeout".to_string(),
                message: format!("rendering did not finish within timeout_ms={timeout_ms}"),
                line: None,
                column: None,
            },
            LimitError::Failed(msg) => ValidationError {
                kind: "render".to_string(),
                message: msg.clone(),
                line: None,
                column: None,
            },
        }
    }

    fn status(&self, timeout_ms: u64) -> Status {
        match self {
            LimitError::TimedOut => Status::err(
                TIMEOUT_EXIT,
                format!("timeout: rendering did not finish within {timeout_ms} ms"),
            ),
            LimitError::Failed(msg) => Status::err(1, msg.clone()),
        }
    }
}

/// Runs `f` on a worker thread and waits at most `timeout_ms` (0 = no
/// limit) for its result. A panic in `f` is reported, not propagated.
fn run_limited<T: Send + 'static>(
    timeout_ms: u64,
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, LimitError> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("template-render".to_string())
        .stack_size(RENDER_STACK_BYTES)
        .spawn(move || {
            // The receiver is gone only after a timeout; the result is
            // then unwanted.
            let _ = tx.send(f());
        })
        .map_err(|e| LimitError::Failed(format!("could not start rendering: {e}")))?;
    let received = if timeout_ms == 0 {
        rx.recv().map_err(|_| RecvError::Disconnected)
    } else {
        rx.recv_timeout(std::time::Duration::from_millis(timeout_ms))
            .map_err(|e| match e {
                std::sync::mpsc::RecvTimeoutError::Timeout => RecvError::Timeout,
                std::sync::mpsc::RecvTimeoutError::Disconnected => RecvError::Disconnected,
            })
    };
    received.map_err(|e| match e {
        RecvError::Timeout => LimitError::TimedOut,
        RecvError::Disconnected => {
            LimitError::Failed("the template engine panicked while rendering".to_string())
        }
    })
}

enum RecvError {
    Timeout,
    Disconnected,
}

/// Results of a `test` run.
struct TestRun {
    cases: Vec<TestCaseResult>,
    /// Number of cases supplied.
    planned: usize,
    /// Set when the run stopped before finishing (timeout or panic).
    stopped: Option<LimitError>,
}

/// Runs the cases on a worker thread, collecting each result as it
/// finishes, so a timeout still reports the cases that ran.
fn run_test_cases(
    tera: Tera,
    cases: Vec<TemplateTestCase>,
    stop_on_first_fail: bool,
    capture_output: String,
    timeout_ms: u64,
) -> TestRun {
    let planned = cases.len();
    let (tx, rx) = std::sync::mpsc::channel::<TestCaseResult>();
    let worker = std::thread::Builder::new()
        .name("template-test".to_string())
        .stack_size(RENDER_STACK_BYTES)
        .spawn(move || {
            for case in &cases {
                let result = run_single_case(&tera, "test_template", case, &capture_output);
                let failed = !result.ok;
                if tx.send(result).is_err() || (stop_on_first_fail && failed) {
                    break;
                }
            }
        });
    let worker = match worker {
        Ok(w) => w,
        Err(e) => {
            return TestRun {
                cases: Vec::new(),
                planned,
                stopped: Some(LimitError::Failed(format!("could not start tests: {e}"))),
            };
        }
    };

    let deadline = (timeout_ms > 0)
        .then(|| std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms));
    let mut results = Vec::new();
    let mut stopped = None;
    loop {
        let next = match deadline {
            None => rx.recv().map_err(|_| RecvError::Disconnected),
            Some(d) => rx
                .recv_timeout(d.saturating_duration_since(std::time::Instant::now()))
                .map_err(|e| match e {
                    std::sync::mpsc::RecvTimeoutError::Timeout => RecvError::Timeout,
                    std::sync::mpsc::RecvTimeoutError::Disconnected => RecvError::Disconnected,
                }),
        };
        match next {
            Ok(result) => results.push(result),
            Err(RecvError::Timeout) => {
                stopped = Some(LimitError::TimedOut);
                break;
            }
            Err(RecvError::Disconnected) => {
                // The worker is done; a panic means cases were skipped.
                if worker.join().is_err() {
                    stopped = Some(LimitError::Failed(
                        "the template engine panicked while rendering".to_string(),
                    ));
                }
                break;
            }
        }
    }
    TestRun {
        cases: results,
        planned,
        stopped,
    }
}

fn run_single_case(
    tera: &Tera,
    template_name: &str,
    test_case: &TemplateTestCase,
    capture_output: &str,
) -> TestCaseResult {
    let failed = |error: String| TestCaseResult {
        name: test_case.name.clone(),
        ok: false,
        error: Some(error),
        expected: test_case.expected.clone(),
        contains: test_case.contains.clone(),
        not_contains: test_case.not_contains.clone(),
        rendered: None,
        diff: None,
    };

    let tera_context = match TeraContext::from_serialize(&test_case.context) {
        Ok(ctx) => ctx,
        Err(e) => return failed(format!("failed to convert context: {}", e)),
    };

    let rendered = match tera.render(template_name, &tera_context) {
        Ok(output) => output,
        Err(e) => return failed(format!("template render error: {}", error_chain(&e))),
    };

    let (ok, error, diff) = check_expectations(test_case, &rendered);

    let rendered_output = match capture_output {
        "none" => None,
        "full" => Some(rendered),
        _ if ok => None,
        _ => Some(rendered),
    };

    TestCaseResult {
        name: test_case.name.clone(),
        ok,
        error,
        expected: test_case.expected.clone(),
        contains: test_case.contains.clone(),
        not_contains: test_case.not_contains.clone(),
        rendered: rendered_output,
        diff,
    }
}

fn check_expectations(
    test_case: &TemplateTestCase,
    rendered: &str,
) -> (bool, Option<String>, Option<String>) {
    if let Some(expected) = &test_case.expected {
        if rendered != expected {
            let diff = format!("Expected: {:?}, Got: {:?}", expected, rendered);
            return (
                false,
                Some("expected output mismatch".to_string()),
                Some(diff),
            );
        }
    }

    if let Some(contains) = &test_case.contains {
        if !rendered.contains(contains) {
            let diff = format!(
                "Expected output to contain: {:?}, but got: {:?}",
                contains, rendered
            );
            return (false, Some("contains check failed".to_string()), Some(diff));
        }
    }

    if let Some(not_contains) = &test_case.not_contains {
        if rendered.contains(not_contains) {
            let diff = format!(
                "Expected output to NOT contain: {:?}, but got: {:?}",
                not_contains, rendered
            );
            return (
                false,
                Some("not_contains check failed".to_string()),
                Some(diff),
            );
        }
    }

    (true, None, None)
}

/// Deepest macro call nesting a template may reach. Deeper calls fail with
/// a render error instead of overflowing the stack and aborting resh.
const MAX_MACRO_DEPTH: i64 = 200;

/// Stack for render threads, sized so `MAX_MACRO_DEPTH` nested macro calls
/// fit with a wide margin (only the pages used are committed).
const RENDER_STACK_BYTES: usize = 256 * 1024 * 1024;

/// Hidden macro argument that carries the current nesting depth.
const DEPTH_ARG: &str = "__resh_macro_depth";

/// Function the depth guard calls; it always fails with the limit message.
const DEPTH_FN: &str = "__resh_macro_depth_exceeded";

/// Compiles `content` as template `name`, with every macro guarded against
/// unbounded recursion (see `guard_macro_depth`).
fn compile(name: &str, content: &str) -> Result<Tera, tera::Error> {
    let mut tera = Tera::default();
    tera.add_raw_template(name, content)?;
    tera.register_function(DEPTH_FN, |_: &std::collections::HashMap<String, Value>| {
        Err(tera::Error::msg(format!(
            "macro calls nested deeper than {MAX_MACRO_DEPTH} levels \
             (a macro that calls itself without end?)"
        )))
    });
    if let Some(template) = tera.templates.get_mut(name) {
        for def in template.macros.values_mut() {
            guard_macro_depth(def);
        }
    }
    Ok(tera)
}

/// Tera has no recursion limit: a macro that calls itself without end
/// overflows the stack, which aborts the process. Each macro gets a hidden
/// depth argument (default 0); every `self::` call made inside a macro body
/// passes depth + 1, and a macro entered past `MAX_MACRO_DEPTH` calls a
/// function that fails the render.
fn guard_macro_depth(def: &mut tera::ast::MacroDefinition) {
    use tera::ast::{Expr, ExprVal, FunctionCall, If, LogicExpr, LogicOperator, Node, WS};
    for node in &mut def.body {
        add_depth_to_node(node);
    }
    def.args
        .insert(DEPTH_ARG.to_string(), Some(Expr::new(ExprVal::Int(0))));
    let too_deep = Expr::new(ExprVal::Logic(LogicExpr {
        lhs: Box::new(Expr::new(ExprVal::Ident(DEPTH_ARG.to_string()))),
        rhs: Box::new(Expr::new(ExprVal::Int(MAX_MACRO_DEPTH))),
        operator: LogicOperator::Gte,
    }));
    let fail = Node::VariableBlock(
        WS::default(),
        Expr::new(ExprVal::FunctionCall(FunctionCall {
            name: DEPTH_FN.to_string(),
            args: Default::default(),
        })),
    );
    let guard = Node::If(
        If {
            conditions: vec![(WS::default(), too_deep, vec![fail])],
            otherwise: None,
        },
        WS::default(),
    );
    def.body.insert(0, guard);
}

fn add_depth_to_nodes(nodes: &mut [tera::ast::Node]) {
    for node in nodes {
        add_depth_to_node(node);
    }
}

fn add_depth_to_node(node: &mut tera::ast::Node) {
    use tera::ast::Node;
    match node {
        Node::VariableBlock(_, e) => add_depth_to_expr(e),
        Node::Set(_, set) => add_depth_to_expr(&mut set.value),
        Node::FilterSection(_, section, _) => {
            add_depth_to_call_args(&mut section.filter);
            add_depth_to_nodes(&mut section.body);
        }
        Node::Block(_, block, _) => add_depth_to_nodes(&mut block.body),
        Node::Forloop(_, forloop, _) => {
            add_depth_to_expr(&mut forloop.container);
            add_depth_to_nodes(&mut forloop.body);
            if let Some(empty) = &mut forloop.empty_body {
                add_depth_to_nodes(empty);
            }
        }
        Node::If(cond, _) => {
            for (_, e, body) in &mut cond.conditions {
                add_depth_to_expr(e);
                add_depth_to_nodes(body);
            }
            if let Some((_, body)) = &mut cond.otherwise {
                add_depth_to_nodes(body);
            }
        }
        // Macro definitions are guarded separately; the rest hold no
        // expressions.
        _ => {}
    }
}

fn add_depth_to_call_args(call: &mut tera::ast::FunctionCall) {
    for e in call.args.values_mut() {
        add_depth_to_expr(e);
    }
}

fn add_depth_to_expr(expr: &mut tera::ast::Expr) {
    for filter in &mut expr.filters {
        add_depth_to_call_args(filter);
    }
    add_depth_to_val(&mut expr.val);
}

fn add_depth_to_val(val: &mut tera::ast::ExprVal) {
    use tera::ast::{Expr, ExprVal, MathExpr, MathOperator};
    match val {
        ExprVal::Math(m) => {
            add_depth_to_expr(&mut m.lhs);
            add_depth_to_expr(&mut m.rhs);
        }
        ExprVal::Logic(l) => {
            add_depth_to_expr(&mut l.lhs);
            add_depth_to_expr(&mut l.rhs);
        }
        ExprVal::In(i) => {
            add_depth_to_expr(&mut i.lhs);
            add_depth_to_expr(&mut i.rhs);
        }
        ExprVal::Test(t) => t.args.iter_mut().for_each(add_depth_to_expr),
        ExprVal::FunctionCall(f) => add_depth_to_call_args(f),
        ExprVal::Array(items) => items.iter_mut().for_each(add_depth_to_expr),
        ExprVal::StringConcat(s) => s.values.iter_mut().for_each(add_depth_to_val),
        ExprVal::MacroCall(call) => {
            for e in call.args.values_mut() {
                add_depth_to_expr(e);
            }
            if call.namespace == "self" {
                call.args.insert(
                    DEPTH_ARG.to_string(),
                    Expr::new(ExprVal::Math(MathExpr {
                        lhs: Box::new(Expr::new(ExprVal::Ident(DEPTH_ARG.to_string()))),
                        rhs: Box::new(Expr::new(ExprVal::Int(1))),
                        operator: MathOperator::Add,
                    })),
                );
            }
        }
        ExprVal::String(_)
        | ExprVal::Int(_)
        | ExprVal::Float(_)
        | ExprVal::Bool(_)
        | ExprVal::Ident(_) => {}
    }
}

impl TemplateHandle {
    pub fn from_url(url: Url) -> Result<TemplateHandle, anyhow::Error> {
        // Check for help flags first
        let path_str = if url.host_str().is_some() && !url.host_str().unwrap().is_empty() {
            let host = url.host_str().unwrap();
            let path = url.path();
            if path == "/" || path.is_empty() {
                // Just the host: template://filename.html
                host.to_string()
            } else {
                // Host + path: template://dir/subdir/filename.html
                format!("{}{}", host, path)
            }
        } else {
            // No host, just path: template:///path/to/file.html
            let path = url.path();
            if path.starts_with('/') {
                path[1..].to_string() // Remove leading slash
            } else {
                path.to_string()
            }
        };

        // Check for help flags in various positions
        let is_help_request = path_str == "--help"
            || path_str == "-h"
            || path_str.ends_with(".--help")
            || path_str.ends_with(".-h");

        // Extract verb-specific help if provided (e.g., --help=render)
        let help_verb = url.query_pairs().find_map(|(k, v)| {
            if k == "help" || (k == "--help" && !v.is_empty()) {
                Some(v.to_string())
            } else {
                None
            }
        });

        // If this is a help request, return early
        if is_help_request || help_verb.is_some() {
            return Ok(TemplateHandle {
                template_path: None,
                is_help_request: true,
                help_verb,
            });
        }

        // For template URLs, we want to combine host and path to get the full template path
        // e.g., template://tests/fixtures/templates/hello.html should give us
        // "tests/fixtures/templates/hello.html" not just "tests"

        // Check for special inline case
        if path_str.is_empty() || path_str == "/" || path_str == "/inline" || path_str == "inline" {
            return Ok(TemplateHandle {
                template_path: None,
                is_help_request: false,
                help_verb: None,
            });
        }

        // Decode URL encoding and escape sequences
        let decoded = percent_decode_str(&path_str)
            .decode_utf8_lossy()
            .to_string();
        let unescaped = unescape_backslashes(&decoded);
        let path = PathBuf::from(unescaped);
        let normalized = normalize_path(&path);

        Ok(TemplateHandle {
            template_path: Some(normalized),
            is_help_request: false,
            help_verb: None,
        })
    }

    /// Template text from the arguments (`template`, then `from`, then, for
    /// validate only, the older `inline`), or `None` to use the file.
    fn inline_source<'a>(args: &'a Args, verb: &str) -> Option<&'a String> {
        args.get("template")
            .or_else(|| args.get("from"))
            .or_else(|| {
                if verb == "validate" {
                    args.get("inline")
                } else {
                    None
                }
            })
    }

    /// Reads the template text: an inline argument or the template file.
    fn read_template(&self, args: &Args, verb: &str) -> Result<String, ValidationError> {
        if let Some(text) = Self::inline_source(args, verb) {
            return Ok(text.clone());
        }
        match &self.template_path {
            Some(path) => std::fs::read_to_string(path).map_err(|e| ValidationError {
                kind: if e.kind() == std::io::ErrorKind::NotFound {
                    "template_not_found".to_string()
                } else {
                    "io".to_string()
                },
                message: format!("failed to read template file '{}': {}", path.display(), e),
                line: None,
                column: None,
            }),
            None => Err(ValidationError {
                kind: "template_not_found".to_string(),
                message: "no template source provided (missing 'template' argument or file path)"
                    .to_string(),
                line: None,
                column: None,
            }),
        }
    }

    fn create_template_info(
        &self,
        args: &Args,
        verb: &str,
        template_content: Option<&str>,
    ) -> TemplateInfo {
        if Self::inline_source(args, verb).is_some() {
            TemplateInfo {
                source: "inline".to_string(),
                name: "inline".to_string(),
                path: None,
                size: template_content.map(|s| s.len()),
            }
        } else if let Some(path) = &self.template_path {
            TemplateInfo {
                source: "file".to_string(),
                name: path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
                path: Some(path.to_string_lossy().to_string()),
                size: template_content.map(|s| s.len()),
            }
        } else {
            TemplateInfo {
                source: "inline".to_string(),
                name: "inline".to_string(),
                path: None,
                size: template_content.map(|s| s.len()),
            }
        }
    }

    /// Builds the context from `context_file` and `context` (`context`
    /// replaces `context_file` entirely when both are given).
    fn parse_render_context(
        &self,
        args: &Args,
    ) -> Result<(ContextInfo, TeraContext), ValidationError> {
        let mut context_value = Value::Object(serde_json::Map::new());

        // Parse context_file first (lower priority)
        if let Some(context_file_path) = args.get("context_file") {
            match std::fs::read_to_string(context_file_path) {
                Ok(content) => match serde_json::from_str::<Value>(&content) {
                    Ok(file_value) => {
                        context_value = file_value;
                    }
                    Err(e) => {
                        return Err(ValidationError {
                            kind: "context_parse".to_string(),
                            message: format!("failed to parse context_file JSON: {}", e),
                            line: None,
                            column: None,
                        });
                    }
                },
                Err(e) => {
                    return Err(ValidationError {
                        kind: "io".to_string(),
                        message: format!("failed to read context_file: {}", e),
                        line: None,
                        column: None,
                    });
                }
            }
        }

        // Parse context argument (higher priority - overrides context_file)
        if let Some(context_str) = args.get("context") {
            if !context_str.trim().is_empty() {
                match serde_json::from_str::<Value>(context_str) {
                    Ok(value) => {
                        context_value = value;
                    }
                    Err(e) => {
                        return Err(ValidationError {
                            kind: "context_parse".to_string(),
                            message: format!("failed to parse context JSON: {}", e),
                            line: None,
                            column: None,
                        });
                    }
                }
            }
        }

        // Extract keys for ContextInfo
        let keys = match &context_value {
            Value::Object(map) => map.keys().cloned().collect(),
            _ => Vec::new(),
        };

        let context_info = ContextInfo {
            keys,
            raw: context_value.clone(),
        };

        // Convert to Tera context (the context must be a JSON object)
        let tera_context = match TeraContext::from_serialize(&context_value) {
            Ok(ctx) => ctx,
            Err(e) => {
                return Err(ValidationError {
                    kind: "context_parse".to_string(),
                    message: format!("failed to convert context to Tera context: {}", e),
                    line: None,
                    column: None,
                });
            }
        };

        Ok((context_info, tera_context))
    }

    fn format_render_output(
        &self,
        rendered: String,
        format: &str,
    ) -> Result<BodyInfo, ValidationError> {
        match format {
            "text" => Ok(BodyInfo {
                body_type: "text".to_string(),
                value: Some(Value::String(rendered)),
                base64: None,
            }),
            "html" => Ok(BodyInfo {
                body_type: "html".to_string(),
                value: Some(Value::String(rendered)),
                base64: None,
            }),
            "json" => match serde_json::from_str::<Value>(&rendered) {
                Ok(json_value) => Ok(BodyInfo {
                    body_type: "json".to_string(),
                    value: Some(json_value),
                    base64: None,
                }),
                Err(e) => Err(ValidationError {
                    kind: "json_parse".to_string(),
                    message: format!("failed to parse rendered output as JSON: {}", e),
                    line: None,
                    column: None,
                }),
            },
            "bytes" => {
                use base64::{Engine as _, engine::general_purpose};
                let base64_encoded = general_purpose::STANDARD.encode(rendered.as_bytes());
                Ok(BodyInfo {
                    body_type: "bytes".to_string(),
                    value: None,
                    base64: Some(base64_encoded),
                })
            }
            _ => Err(invalid_format_error(format)),
        }
    }

    /// Checks every argument before anything is read or rendered. Returns
    /// the parsed options, or the error to report (exit 2).
    fn check_args(verb: &str, args: &Args) -> Result<Options, ValidationError> {
        let allowed = verb_args(verb).unwrap_or(&[]);
        let mut keys: Vec<&String> = args.keys().collect();
        keys.sort();
        // dry_run=true is refused by the dispatcher for every template verb;
        // dry_run=false changes nothing.
        if let Some(bad) = keys
            .into_iter()
            .find(|k| k.as_str() != "dry_run" && !allowed.contains(&k.as_str()))
        {
            return Err(invalid_argument(format!(
                "unknown argument for template {verb}: {bad}{} (accepted: {})",
                did_you_mean(bad, allowed),
                allowed.join(", ")
            )));
        }
        let bool_arg = |key: &str, default: bool| -> Result<bool, ValidationError> {
            crate::core::lenient::bool_arg(args, key)
                .map(|v| v.unwrap_or(default))
                .map_err(|e| invalid_argument(e.to_string()))
        };
        let timeout_ms = match args.get("timeout_ms") {
            None => 0,
            Some(v) => v.trim().parse::<u64>().map_err(|_| {
                invalid_argument(format!(
                    "invalid timeout_ms value: {v:?} (expected a non-negative integer)"
                ))
            })?,
        };
        let mut opts = Options {
            timeout_ms,
            strict: true,
            stop_on_first_fail: false,
            capture_output: "summary".to_string(),
            format: "text".to_string(),
        };
        match verb {
            "render" => {
                let format = args.get("format").map(String::as_str).unwrap_or("text");
                if !["text", "html", "json", "bytes"].contains(&format) {
                    return Err(invalid_format_error(format));
                }
                opts.format = format.to_string();
            }
            "validate" => {
                opts.strict = bool_arg("strict", true)?;
                let encoding = args.get("encoding").map(|s| s.as_str()).unwrap_or("utf-8");
                if !encoding.eq_ignore_ascii_case("utf-8") {
                    return Err(ValidationError {
                        kind: "encoding".to_string(),
                        message: format!(
                            "unsupported encoding: {}. Only utf-8 is supported",
                            encoding
                        ),
                        line: None,
                        column: None,
                    });
                }
            }
            "test" => {
                opts.stop_on_first_fail = bool_arg("stop_on_first_fail", false)?;
                let capture = args
                    .get("capture_output")
                    .map(String::as_str)
                    .unwrap_or("summary");
                if !["none", "summary", "full"].contains(&capture) {
                    return Err(invalid_argument(format!(
                        "invalid capture_output value: {capture:?} (expected none, summary or full)"
                    )));
                }
                opts.capture_output = capture.to_string();
            }
            _ => {}
        }
        Ok(opts)
    }

    fn validate(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let mut result = ValidationResult {
            ok: false,
            template: self.create_template_info(args, "validate", None),
            strict: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        };
        let emit = |result: &ValidationResult, io: &mut IoStreams| -> Result<()> {
            writeln!(io.stdout, "{}", serde_json::to_string(result)?)?;
            Ok(())
        };

        let opts = match Self::check_args("validate", args) {
            Ok(opts) => opts,
            Err(error) => {
                result.strict = crate::core::lenient::bool_arg(args, "strict")
                    .ok()
                    .flatten()
                    .unwrap_or(true);
                let kind = error.kind.clone();
                result.errors.push(error);
                emit(&result, io)?;
                return Ok(Status::err(2, kind));
            }
        };
        let strict = opts.strict;
        result.strict = strict;

        let template_content = match self.read_template(args, "validate") {
            Ok(content) => content,
            Err(e) => {
                result.errors.push(ValidationError {
                    kind: "file_read".to_string(),
                    message: format!("Failed to read template: {}", e.message),
                    line: None,
                    column: None,
                });
                emit(&result, io)?;
                return Ok(Status::err(
                    self.source_error_code(),
                    "Failed to read template",
                ));
            }
        };
        result.template = self.create_template_info(args, "validate", Some(&template_content));

        let context = match self.parse_render_context(args) {
            Ok((_, ctx)) => ctx,
            Err(mut error) => {
                if error.kind == "io" {
                    error.kind = "file_read".to_string();
                }
                result.errors.push(error);
                emit(&result, io)?;
                return Ok(Status::err(1, "Context parsing failed"));
            }
        };

        // Compile, then render with the context to find missing variables,
        // within timeout_ms.
        let outcome = run_limited(opts.timeout_ms, move || {
            let tera = match compile("validate_template", &template_content) {
                Ok(tera) => tera,
                Err(e) => return Err((true, error_chain(&e), missing_variable_message(&e))),
            };
            tera.render("validate_template", &context)
                .map(|_| ())
                .map_err(|e| (false, error_chain(&e), missing_variable_message(&e)))
        });

        match outcome {
            Err(limit) => {
                result.errors.push(limit.error(opts.timeout_ms));
                emit(&result, io)?;
                return Ok(limit.status(opts.timeout_ms));
            }
            Ok(Ok(())) => result.ok = true,
            Ok(Err((true, chain, _))) => {
                result.errors.push(ValidationError {
                    kind: "syntax".to_string(),
                    message: format!("Template syntax error: {}", chain),
                    line: None,
                    column: None,
                });
                emit(&result, io)?;
                return Ok(Status::err(1, "Template syntax error"));
            }
            Ok(Err((false, _, Some(detail)))) => {
                let validation_error = ValidationError {
                    kind: "missing_variable".to_string(),
                    message: format!("Missing variable: {}", detail),
                    line: None,
                    column: None,
                };
                if strict {
                    result.errors.push(validation_error);
                } else {
                    result.ok = true;
                    result.warnings.push(validation_error);
                }
            }
            Ok(Err((false, chain, None))) => {
                result.errors.push(ValidationError {
                    kind: "render".to_string(),
                    message: format!("Template render error: {}", chain),
                    line: None,
                    column: None,
                });
            }
        }

        emit(&result, io)?;
        if result.ok {
            Ok(Status::ok())
        } else {
            Ok(Status::err(1, "Template validation failed"))
        }
    }

    fn render_template(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let empty_context = || ContextInfo {
            keys: Vec::new(),
            raw: Value::Object(serde_json::Map::new()),
        };
        let fail = |template: TemplateInfo,
                    context: ContextInfo,
                    error: ValidationError,
                    status: Status,
                    io: &mut IoStreams|
         -> Result<Status> {
            let result = RenderResult {
                ok: false,
                engine: "tera".to_string(),
                template,
                context,
                body: None,
                errors: vec![error],
            };
            writeln!(io.stdout, "{}", serde_json::to_string(&result)?)?;
            Ok(status)
        };

        let opts = match Self::check_args("render", args) {
            Ok(opts) => opts,
            Err(error) => {
                let status = Status::err(2, error.kind.clone());
                let info = self.create_template_info(args, "render", None);
                return fail(info, empty_context(), error, status, io);
            }
        };

        let template_content = match self.read_template(args, "render") {
            Ok(content) => content,
            Err(error) => {
                let status = Status::err(self.source_error_code(), error.kind.clone());
                let info = self.create_template_info(args, "render", None);
                return fail(info, empty_context(), error, status, io);
            }
        };
        let info = || self.create_template_info(args, "render", Some(&template_content));

        let (context_info, tera_context) = match self.parse_render_context(args) {
            Ok(parsed) => parsed,
            Err(error) => {
                let status = Status::err(1, error.kind.clone());
                return fail(info(), empty_context(), error, status, io);
            }
        };

        let content = template_content.clone();
        let outcome = run_limited(opts.timeout_ms, move || {
            let tera = match compile("render_template", &content) {
                Ok(tera) => tera,
                Err(e) => return Err(format!("template parse error: {}", error_chain(&e))),
            };
            tera.render("render_template", &tera_context)
                .map_err(|e| format!("template render error: {}", error_chain(&e)))
        });

        let rendered = match outcome {
            Err(limit) => {
                let error = limit.error(opts.timeout_ms);
                return fail(
                    info(),
                    context_info,
                    error,
                    limit.status(opts.timeout_ms),
                    io,
                );
            }
            Ok(Err(message)) => {
                let error = ValidationError {
                    kind: "render".to_string(),
                    message,
                    line: None,
                    column: None,
                };
                let status = Status::err(1, "tera_render_failed");
                return fail(info(), context_info, error, status, io);
            }
            Ok(Ok(rendered)) => rendered,
        };

        let body = match self.format_render_output(rendered, &opts.format) {
            Ok(body_info) => body_info,
            Err(error) => {
                let status = Status::err(1, error.kind.clone());
                return fail(info(), context_info, error, status, io);
            }
        };

        let result = RenderResult {
            ok: true,
            engine: "tera".to_string(),
            template: info(),
            context: context_info,
            body: Some(body),
            errors: Vec::new(),
        };
        writeln!(io.stdout, "{}", serde_json::to_string(&result)?)?;
        Ok(Status::ok())
    }

    fn test_template(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let template_label = |content_name: Option<&str>| -> String {
            content_name.map(str::to_string).unwrap_or_else(|| {
                if Self::inline_source(args, "test").is_some() {
                    "inline".to_string()
                } else {
                    self.template_path
                        .as_ref()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|| "inline".to_string())
                }
            })
        };
        let fail = |template: String,
                    stop_on_first_fail: bool,
                    total: usize,
                    error: String,
                    status: Status,
                    io: &mut IoStreams|
         -> Result<Status> {
            let result = TestResult {
                template,
                ok: false,
                total,
                passed: 0,
                failed: total,
                stop_on_first_fail,
                error: Some(error),
                cases: Vec::new(),
            };
            writeln!(io.stdout, "{}", serde_json::to_string(&result)?)?;
            Ok(status)
        };

        let opts = match Self::check_args("test", args) {
            Ok(opts) => opts,
            Err(error) => {
                let stop = crate::core::lenient::bool_arg(args, "stop_on_first_fail")
                    .ok()
                    .flatten()
                    .unwrap_or(false);
                let status = Status::err(2, error.kind.clone());
                return fail(template_label(None), stop, 0, error.message, status, io);
            }
        };
        let stop_on_first_fail = opts.stop_on_first_fail;
        let label = template_label(None);

        let template_content = match self.read_template(args, "test") {
            Ok(content) => content,
            Err(error) => {
                let status = Status::err(self.source_error_code(), "template_not_found");
                return fail(label, stop_on_first_fail, 0, error.message, status, io);
            }
        };

        let test_cases = match self.load_test_cases(args) {
            Ok(cases) => cases,
            Err((code, e)) => {
                let status = Status::err(code, "no_test_cases");
                return fail(label, stop_on_first_fail, 0, format!("{:#}", e), status, io);
            }
        };

        if test_cases.is_empty() {
            let status = Status::err(1, "no_test_cases");
            let message = "no test cases supplied".to_string();
            return fail(label, stop_on_first_fail, 0, message, status, io);
        }

        let tera = match compile("test_template", &template_content) {
            Ok(tera) => tera,
            Err(e) => {
                let n = test_cases.len();
                let message = format!("template parse error: {}", error_chain(&e));
                let status = Status::err(1, "tera_parse_failed");
                return fail(label, stop_on_first_fail, n, message, status, io);
            }
        };

        let run = run_test_cases(
            tera,
            test_cases,
            stop_on_first_fail,
            opts.capture_output.clone(),
            opts.timeout_ms,
        );

        let passed = run.cases.iter().filter(|c| c.ok).count();
        let failed = run.cases.len() - passed;
        let ok = failed == 0 && !run.cases.is_empty() && run.stopped.is_none();
        let status = match &run.stopped {
            Some(limit) => limit.status(opts.timeout_ms),
            None if ok => Status::ok(),
            None => Status::err(1, "tests_failed"),
        };
        let result = TestResult {
            template: label,
            ok,
            total: run.cases.len(),
            passed,
            failed,
            stop_on_first_fail,
            error: run.stopped.map(|limit| {
                format!(
                    "{} ({} of {} cases ran)",
                    limit.error(opts.timeout_ms).message,
                    run.cases.len(),
                    run.planned
                )
            }),
            cases: run.cases,
        };
        writeln!(io.stdout, "{}", serde_json::to_string(&result)?)?;
        Ok(status)
    }

    /// Exit code when the template cannot be read: 2 when no template was
    /// given at all (usage), 1 when the named file is missing or unreadable.
    fn source_error_code(&self) -> i32 {
        if self.template_path.is_some() { 1 } else { 2 }
    }

    /// The test cases, or the exit code and error: 2 for invalid usage (no
    /// cases given, `cases=` not a JSON case list), 1 when a cases file
    /// cannot be read or parsed.
    fn load_test_cases(
        &self,
        args: &Args,
    ) -> std::result::Result<Vec<TemplateTestCase>, (i32, anyhow::Error)> {
        // Priority: 1. inline cases, 2. cases_file, 3. default test file
        if let Some(cases_json) = args.get("cases") {
            return serde_json::from_str(cases_json)
                .with_context(|| "failed to parse inline cases JSON")
                .map_err(|e| (2, e));
        }
        self.load_case_files(args).map_err(|e| {
            let code = if e.is::<NoCases>() { 2 } else { 1 };
            (code, e)
        })
    }

    fn load_case_files(&self, args: &Args) -> Result<Vec<TemplateTestCase>> {
        if let Some(cases_file) = args.get("cases_file") {
            let content = std::fs::read_to_string(cases_file)
                .with_context(|| format!("failed to read cases file: {}", cases_file))?;
            let cases: Vec<TemplateTestCase> = serde_json::from_str(&content)
                .with_context(|| format!("failed to parse cases file JSON: {}", cases_file))?;
            return Ok(cases);
        }

        // Try default test file
        if let Some(template_path) = &self.template_path {
            let default_test_file = template_path.with_extension("tests.json");
            if default_test_file.exists() {
                let content = std::fs::read_to_string(&default_test_file).with_context(|| {
                    format!(
                        "failed to read default test file: {}",
                        default_test_file.display()
                    )
                })?;
                let cases: Vec<TemplateTestCase> =
                    serde_json::from_str(&content).with_context(|| {
                        format!(
                            "failed to parse default test file JSON: {}",
                            default_test_file.display()
                        )
                    })?;
                return Ok(cases);
            }
        }

        Err(NoCases.into())
    }

    /// Writes the approved help, for the whole handle or for one verb.
    fn display_help(&self, verb: Option<&str>, io: &mut IoStreams) -> Result<Status> {
        if let Some(v) = verb {
            if !self.verbs().contains(&v) {
                writeln!(io.stderr, "Unknown verb: {}. Use --help for full list.", v)?;
                return Ok(Status {
                    ok: false,
                    code: Some(1),
                    reason: Some("unknown_verb".to_string()),
                });
            }
        }
        write!(
            io.stdout,
            "{}",
            crate::core::help::render_legacy("template", &TEMPLATE_HELP, self.verbs(), verb)
        )?;
        Ok(Status {
            ok: true,
            code: Some(0),
            reason: None,
        })
    }
}

impl Handle for TemplateHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &["render", "validate", "test"]
    }

    fn help(&self) -> Option<&'static HandleHelp> {
        Some(&TEMPLATE_HELP)
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Check if this is a help request
        if self.is_help_request {
            return self.display_help(self.help_verb.as_deref(), io);
        }

        // Normal operation - dispatch to appropriate verb
        match verb {
            "render" => self.render_template(args, io),
            "validate" => self.validate(args, io),
            "test" => self.test_template(args, io),
            _ => Ok(Status::err(2, format!("unknown verb: {}", verb))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::Cursor;
    use std::io::Write;
    use tempfile::TempDir;
    use url::Url;

    fn create_test_io() -> (Cursor<Vec<u8>>, Cursor<Vec<u8>>, Cursor<Vec<u8>>) {
        (
            Cursor::new(Vec::new()), // stdin
            Cursor::new(Vec::new()), // stdout
            Cursor::new(Vec::new()), // stderr
        )
    }

    // VALIDATE TESTS (NEW TERA FUNCTIONALITY)

    #[test]
    fn validate_syntax_ok_without_data() {
        let handle = TemplateHandle {
            template_path: None,
            is_help_request: false,
            help_verb: None,
        };
        let mut args = HashMap::new();
        args.insert(
            "from".to_string(),
            "Hello {{ name | default(value=\"world\") }}!".to_string(),
        );
        args.insert("strict".to_string(), "true".to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.validate(&args, &mut io).unwrap();
        assert!(result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: ValidationResult = serde_json::from_str(&output).unwrap();
        assert!(parsed.ok);
        assert_eq!(parsed.errors.len(), 0);
    }

    #[test]
    fn validate_syntax_error() {
        let handle = TemplateHandle {
            template_path: None,
            is_help_request: false,
            help_verb: None,
        };
        let mut args = HashMap::new();
        args.insert("from".to_string(), "Hello {{ name ".to_string()); // Missing closing braces
        args.insert("strict".to_string(), "true".to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.validate(&args, &mut io).unwrap();
        assert!(!result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: ValidationResult = serde_json::from_str(&output).unwrap();
        assert!(!parsed.ok);
        assert!(parsed.errors.len() > 0);
        assert_eq!(parsed.errors[0].kind, "syntax");
    }

    #[test]
    fn validate_with_data_missing_variable_strict() {
        let handle = TemplateHandle {
            template_path: None,
            is_help_request: false,
            help_verb: None,
        };
        let mut args = HashMap::new();
        args.insert("from".to_string(), "Hello {{ name }}!".to_string());
        args.insert("context".to_string(), "{}".to_string());
        args.insert("strict".to_string(), "true".to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.validate(&args, &mut io).unwrap();
        assert!(!result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: ValidationResult = serde_json::from_str(&output).unwrap();
        assert!(!parsed.ok);
        assert!(parsed.errors.len() > 0);
        assert_eq!(parsed.errors[0].kind, "missing_variable");
    }

    #[test]
    fn validate_with_data_missing_variable_non_strict() {
        let handle = TemplateHandle {
            template_path: None,
            is_help_request: false,
            help_verb: None,
        };
        let mut args = HashMap::new();
        args.insert("from".to_string(), "Hello {{ name }}!".to_string());
        args.insert("context".to_string(), "{}".to_string());
        args.insert("strict".to_string(), "false".to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.validate(&args, &mut io).unwrap();
        assert!(result.ok); // Should succeed in non-strict mode

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: ValidationResult = serde_json::from_str(&output).unwrap();
        assert!(parsed.ok);
        // Should have warnings instead of errors
        assert!(parsed.warnings.len() > 0);
        assert_eq!(parsed.warnings[0].kind, "missing_variable");
    }

    #[test]
    fn validate_bad_json() {
        let handle = TemplateHandle {
            template_path: None,
            is_help_request: false,
            help_verb: None,
        };
        let mut args = HashMap::new();
        args.insert("from".to_string(), "Hello {{ name }}!".to_string());
        args.insert("context".to_string(), "{not valid json}".to_string());
        args.insert("strict".to_string(), "true".to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.validate(&args, &mut io).unwrap();
        assert!(!result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: ValidationResult = serde_json::from_str(&output).unwrap();
        assert!(!parsed.ok);
        assert!(parsed.errors.len() > 0);
        assert_eq!(parsed.errors[0].kind, "context_parse");
    }

    // RENDER TESTS (NEW STRUCTURED OUTPUT)

    #[test]
    fn render_inline_basic() {
        let handle = TemplateHandle {
            template_path: None,
            is_help_request: false,
            help_verb: None,
        };
        let mut args = HashMap::new();
        args.insert("template".to_string(), "Hello {{ name }}".to_string());
        args.insert("context".to_string(), r#"{"name": "Alice"}"#.to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.render_template(&args, &mut io).unwrap();
        assert!(result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: RenderResult = serde_json::from_str(&output).unwrap();
        assert!(parsed.ok);
        assert_eq!(parsed.engine, "tera");
        assert_eq!(parsed.template.source, "inline");
        assert_eq!(parsed.context.keys, vec!["name"]);
        assert_eq!(parsed.body.as_ref().unwrap().body_type, "text");
        assert_eq!(
            parsed.body.as_ref().unwrap().value,
            Some(Value::String("Hello Alice".to_string()))
        );
        assert!(parsed.errors.is_empty());
    }

    #[test]
    fn render_file_with_data_json() {
        let temp_dir = TempDir::new().unwrap();
        let template_path = temp_dir.path().join("welcome.tera");
        let mut template_file = File::create(&template_path).unwrap();
        template_file
            .write_all(b"Hi {{ user }} from {{ env }}")
            .unwrap();

        let handle = TemplateHandle {
            template_path: Some(template_path),
            is_help_request: false,
            help_verb: None,
        };
        let mut args = HashMap::new();
        args.insert(
            "context".to_string(),
            r#"{"user":"bob", "env":"prod"}"#.to_string(),
        );

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.render_template(&args, &mut io).unwrap();
        assert!(result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: RenderResult = serde_json::from_str(&output).unwrap();
        assert!(parsed.ok);
        assert_eq!(parsed.template.source, "file");
        assert_eq!(
            parsed.body.as_ref().unwrap().value,
            Some(Value::String("Hi bob from prod".to_string()))
        );
    }

    #[test]
    fn render_format_json() {
        let handle = TemplateHandle {
            template_path: None,
            is_help_request: false,
            help_verb: None,
        };
        let mut args = HashMap::new();
        args.insert("template".to_string(), r#"{"value": {{ n }}}"#.to_string());
        args.insert("context".to_string(), r#"{"n": 42}"#.to_string());
        args.insert("format".to_string(), "json".to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.render_template(&args, &mut io).unwrap();
        assert!(result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: RenderResult = serde_json::from_str(&output).unwrap();
        assert!(parsed.ok);
        assert_eq!(parsed.body.as_ref().unwrap().body_type, "json");

        let expected_value = serde_json::json!({"value": 42});
        assert_eq!(parsed.body.as_ref().unwrap().value, Some(expected_value));
    }

    #[test]
    fn render_format_bytes() {
        let handle = TemplateHandle {
            template_path: None,
            is_help_request: false,
            help_verb: None,
        };
        let mut args = HashMap::new();
        args.insert("template".to_string(), "Hello {{ name }}".to_string());
        args.insert("context".to_string(), r#"{"name": "world"}"#.to_string());
        args.insert("format".to_string(), "bytes".to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.render_template(&args, &mut io).unwrap();
        assert!(result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: RenderResult = serde_json::from_str(&output).unwrap();
        assert!(parsed.ok);
        assert_eq!(parsed.body.as_ref().unwrap().body_type, "bytes");
        assert!(parsed.body.as_ref().unwrap().value.is_none());
        assert!(parsed.body.as_ref().unwrap().base64.is_some());

        // Decode base64 and verify content
        use base64::{Engine as _, engine::general_purpose};
        let decoded = general_purpose::STANDARD
            .decode(parsed.body.as_ref().unwrap().base64.as_ref().unwrap())
            .unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "Hello world");
    }

    #[test]
    fn render_context_file() {
        let temp_dir = TempDir::new().unwrap();
        let context_path = temp_dir.path().join("context.json");
        let mut context_file = File::create(&context_path).unwrap();
        write!(
            context_file,
            r##"{{"greeting": "Hi", "target": "universe"}}"##
        )
        .unwrap();

        let handle = TemplateHandle {
            template_path: None,
            is_help_request: false,
            help_verb: None,
        };
        let mut args = HashMap::new();
        args.insert(
            "template".to_string(),
            "{{ greeting }} {{ target }}!".to_string(),
        );
        args.insert(
            "context_file".to_string(),
            context_path.to_string_lossy().to_string(),
        );

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.render_template(&args, &mut io).unwrap();
        assert!(result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: RenderResult = serde_json::from_str(&output).unwrap();
        assert!(parsed.ok);
        assert_eq!(
            parsed.body.as_ref().unwrap().value,
            Some(Value::String("Hi universe!".to_string()))
        );
        assert_eq!(parsed.context.keys.len(), 2);
        assert!(parsed.context.keys.contains(&"greeting".to_string()));
        assert!(parsed.context.keys.contains(&"target".to_string()));
    }

    #[test]
    fn render_missing_variable_error() {
        let handle = TemplateHandle {
            template_path: None,
            is_help_request: false,
            help_verb: None,
        };
        let mut args = HashMap::new();
        args.insert("template".to_string(), "Hello {{ missing }}".to_string());
        args.insert("context".to_string(), "{}".to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.render_template(&args, &mut io).unwrap();
        assert!(!result.ok);
        assert_eq!(result.code, Some(1));

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: RenderResult = serde_json::from_str(&output).unwrap();
        assert!(!parsed.ok);
        assert_eq!(parsed.errors[0].kind, "render");
        assert!(parsed.body.is_none());
    }

    #[test]
    fn render_missing_template_source_fails() {
        let handle = TemplateHandle {
            template_path: None,
            is_help_request: false,
            help_verb: None,
        };
        let args = HashMap::new(); // No 'template' or file path

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.render_template(&args, &mut io).unwrap();
        assert!(!result.ok);
        assert_eq!(result.code, Some(2));

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: RenderResult = serde_json::from_str(&output).unwrap();
        assert!(!parsed.ok);
        assert_eq!(parsed.errors[0].kind, "template_not_found");
    }

    #[test]
    fn render_invalid_json_context_fails() {
        let handle = TemplateHandle {
            template_path: None,
            is_help_request: false,
            help_verb: None,
        };
        let mut args = HashMap::new();
        args.insert("template".to_string(), "{{ test }}".to_string());
        args.insert("context".to_string(), "{bad json}".to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.render_template(&args, &mut io).unwrap();
        assert!(!result.ok);
        assert_eq!(result.code, Some(1));

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: RenderResult = serde_json::from_str(&output).unwrap();
        assert!(!parsed.ok);
        assert_eq!(parsed.errors[0].kind, "context_parse");
    }

    #[test]
    fn render_invalid_format_fails() {
        let handle = TemplateHandle {
            template_path: None,
            is_help_request: false,
            help_verb: None,
        };
        let mut args = HashMap::new();
        args.insert("template".to_string(), "Hello world".to_string());
        args.insert("format".to_string(), "invalid_format".to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.render_template(&args, &mut io).unwrap();
        assert!(!result.ok);
        // An invalid format is an argument error, refused before rendering.
        assert_eq!(result.code, Some(2));

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: RenderResult = serde_json::from_str(&output).unwrap();
        assert!(!parsed.ok);
        assert_eq!(parsed.errors[0].kind, "invalid_format");
    }

    #[test]
    fn render_invalid_json_output_fails() {
        let handle = TemplateHandle {
            template_path: None,
            is_help_request: false,
            help_verb: None,
        };
        let mut args = HashMap::new();
        args.insert("template".to_string(), "not valid json".to_string());
        args.insert("format".to_string(), "json".to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.render_template(&args, &mut io).unwrap();
        assert!(!result.ok);
        assert_eq!(result.code, Some(1));

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: RenderResult = serde_json::from_str(&output).unwrap();
        assert!(!parsed.ok);
        assert_eq!(parsed.errors[0].kind, "json_parse");
    }

    #[test]
    fn render_context_overrides_context_file() {
        let temp_dir = TempDir::new().unwrap();
        let context_path = temp_dir.path().join("context.json");
        let mut context_file = File::create(&context_path).unwrap();
        context_file.write_all(br#"{"name": "file"}"#).unwrap();

        let handle = TemplateHandle {
            template_path: None,
            is_help_request: false,
            help_verb: None,
        };
        let mut args = HashMap::new();
        args.insert("template".to_string(), "Hello {{ name }}".to_string());
        args.insert(
            "context_file".to_string(),
            context_path.to_string_lossy().to_string(),
        );
        args.insert("context".to_string(), r#"{"name": "arg"}"#.to_string()); // Should override file

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.render_template(&args, &mut io).unwrap();
        assert!(result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: RenderResult = serde_json::from_str(&output).unwrap();
        assert!(parsed.ok);
        assert_eq!(
            parsed.body.as_ref().unwrap().value,
            Some(Value::String("Hello arg".to_string()))
        );
    }

    // TEST VERB TESTS

    #[test]
    fn test_inline_cases_all_pass() {
        let handle = TemplateHandle {
            template_path: None,
            is_help_request: false,
            help_verb: None,
        };
        let mut args = HashMap::new();
        args.insert("template".to_string(), "Hello {{ name }}!".to_string());
        args.insert(
            "cases".to_string(),
            r#"[
            {
                "name": "basic_test",
                "context": {"name": "Alice"},
                "expected": "Hello Alice!"
            },
            {
                "name": "contains_test",
                "context": {"name": "Bob"},
                "contains": "Bob"
            }
        ]"#
            .to_string(),
        );

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.test_template(&args, &mut io).unwrap();
        assert!(result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: TestResult = serde_json::from_str(&output).unwrap();
        assert!(parsed.ok);
        assert_eq!(parsed.total, 2);
        assert_eq!(parsed.passed, 2);
        assert_eq!(parsed.failed, 0);
        assert_eq!(parsed.cases.len(), 2);
        assert!(parsed.cases[0].ok);
        assert!(parsed.cases[1].ok);
    }

    #[test]
    fn test_inline_cases_with_failure() {
        let handle = TemplateHandle {
            template_path: None,
            is_help_request: false,
            help_verb: None,
        };
        let mut args = HashMap::new();
        args.insert("template".to_string(), "Hello {{ name }}!".to_string());
        args.insert(
            "cases".to_string(),
            r#"[
            {
                "name": "pass_test",
                "context": {"name": "Alice"},
                "expected": "Hello Alice!"
            },
            {
                "name": "fail_test",
                "context": {"name": "Bob"},
                "expected": "Hi Bob!"
            }
        ]"#
            .to_string(),
        );

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.test_template(&args, &mut io).unwrap();
        assert!(!result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: TestResult = serde_json::from_str(&output).unwrap();
        assert!(!parsed.ok);
        assert_eq!(parsed.total, 2);
        assert_eq!(parsed.passed, 1);
        assert_eq!(parsed.failed, 1);
        assert_eq!(parsed.cases.len(), 2);
        assert!(parsed.cases[0].ok);
        assert!(!parsed.cases[1].ok);
        assert!(parsed.cases[1].error.is_some());
        assert!(parsed.cases[1].diff.is_some());
    }

    #[test]
    fn test_stop_on_first_fail() {
        let handle = TemplateHandle {
            template_path: None,
            is_help_request: false,
            help_verb: None,
        };
        let mut args = HashMap::new();
        args.insert("template".to_string(), "Hello {{ name }}!".to_string());
        args.insert("stop_on_first_fail".to_string(), "true".to_string());
        args.insert(
            "cases".to_string(),
            r#"[
            {
                "name": "fail_test",
                "context": {"name": "Bob"},
                "expected": "Hi Bob!"
            },
            {
                "name": "should_not_run",
                "context": {"name": "Charlie"},
                "expected": "Hello Charlie!"
            }
        ]"#
            .to_string(),
        );

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.test_template(&args, &mut io).unwrap();
        assert!(!result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: TestResult = serde_json::from_str(&output).unwrap();
        assert!(!parsed.ok);
        assert_eq!(parsed.total, 1); // Only first test should run
        assert_eq!(parsed.passed, 0);
        assert_eq!(parsed.failed, 1);
        assert_eq!(parsed.cases.len(), 1); // Only first test result
        assert!(!parsed.cases[0].ok);
        assert!(parsed.stop_on_first_fail);
    }

    #[test]
    fn test_capture_output_modes() {
        let handle = TemplateHandle {
            template_path: None,
            is_help_request: false,
            help_verb: None,
        };
        let mut args = HashMap::new();
        args.insert("template".to_string(), "Hello {{ name }}!".to_string());
        args.insert("capture_output".to_string(), "full".to_string());
        args.insert(
            "cases".to_string(),
            r#"[
            {
                "name": "pass_test",
                "context": {"name": "Alice"},
                "expected": "Hello Alice!"
            }
        ]"#
            .to_string(),
        );

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.test_template(&args, &mut io).unwrap();
        assert!(result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: TestResult = serde_json::from_str(&output).unwrap();
        assert!(parsed.cases[0].rendered.is_some());
        assert_eq!(parsed.cases[0].rendered.as_ref().unwrap(), "Hello Alice!");
    }

    #[test]
    fn test_contains_and_not_contains() {
        let handle = TemplateHandle {
            template_path: None,
            is_help_request: false,
            help_verb: None,
        };
        let mut args = HashMap::new();
        args.insert(
            "template".to_string(),
            "Hello {{ name }}! Welcome to {{ place }}.".to_string(),
        );
        args.insert(
            "cases".to_string(),
            r#"[
            {
                "name": "contains_pass",
                "context": {"name": "Alice", "place": "Earth"},
                "contains": "Alice"
            },
            {
                "name": "not_contains_pass",
                "context": {"name": "Bob", "place": "Mars"},
                "not_contains": "Earth"
            },
            {
                "name": "not_contains_fail",
                "context": {"name": "Charlie", "place": "Earth"},
                "not_contains": "Earth"
            }
        ]"#
            .to_string(),
        );

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.test_template(&args, &mut io).unwrap();
        assert!(!result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: TestResult = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed.total, 3);
        assert_eq!(parsed.passed, 2);
        assert_eq!(parsed.failed, 1);
        assert!(parsed.cases[0].ok); // contains pass
        assert!(parsed.cases[1].ok); // not_contains pass
        assert!(!parsed.cases[2].ok); // not_contains fail
    }

    #[test]
    fn test_no_cases_provided_error() {
        let handle = TemplateHandle {
            template_path: None,
            is_help_request: false,
            help_verb: None,
        };
        let mut args = HashMap::new();
        args.insert("template".to_string(), "Hello {{ name }}!".to_string());
        // No cases, cases_file, or default file

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.test_template(&args, &mut io).unwrap();
        assert!(!result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: TestResult = serde_json::from_str(&output).unwrap();
        assert!(!parsed.ok);
        assert_eq!(parsed.total, 0);
        assert!(parsed.error.is_some());
    }

    #[test]
    fn test_invalid_cases_json() {
        let handle = TemplateHandle {
            template_path: None,
            is_help_request: false,
            help_verb: None,
        };
        let mut args = HashMap::new();
        args.insert("template".to_string(), "Hello {{ name }}!".to_string());
        args.insert("cases".to_string(), "{invalid json}".to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.test_template(&args, &mut io).unwrap();
        assert!(!result.ok);
        assert_eq!(result.code, Some(2));

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: TestResult = serde_json::from_str(&output).unwrap();
        assert!(!parsed.ok);
        assert!(parsed.error.is_some());
        assert!(parsed.error.as_ref().unwrap().contains("parse"));
    }

    #[test]
    fn test_template_render_error() {
        let handle = TemplateHandle {
            template_path: None,
            is_help_request: false,
            help_verb: None,
        };
        let mut args = HashMap::new();
        args.insert(
            "template".to_string(),
            "Hello {{ missing_var }}!".to_string(),
        );
        args.insert(
            "cases".to_string(),
            r#"[
            {
                "name": "missing_var",
                "context": {}
            }
        ]"#
            .to_string(),
        );

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.test_template(&args, &mut io).unwrap();
        assert!(!result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: TestResult = serde_json::from_str(&output).unwrap();
        assert!(!parsed.ok);
        assert_eq!(parsed.total, 1);
        assert_eq!(parsed.failed, 1);
        assert!(!parsed.cases[0].ok);
        assert!(parsed.cases[0].error.is_some());
        assert!(parsed.cases[0].error.as_ref().unwrap().contains("render"));
    }

    #[test]
    fn test_cases_file() {
        let temp_dir = TempDir::new().unwrap();
        let cases_file_path = temp_dir.path().join("test_cases.json");
        let mut cases_file = File::create(&cases_file_path).unwrap();
        cases_file
            .write_all(
                br#"[
            {
                "name": "file_test",
                "context": {"name": "FileTest"},
                "expected": "Hello FileTest!"
            }
        ]"#,
            )
            .unwrap();

        let handle = TemplateHandle {
            template_path: None,
            is_help_request: false,
            help_verb: None,
        };
        let mut args = HashMap::new();
        args.insert("template".to_string(), "Hello {{ name }}!".to_string());
        args.insert(
            "cases_file".to_string(),
            cases_file_path.to_string_lossy().to_string(),
        );

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.test_template(&args, &mut io).unwrap();
        assert!(result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: TestResult = serde_json::from_str(&output).unwrap();
        assert!(parsed.ok);
        assert_eq!(parsed.total, 1);
        assert_eq!(parsed.passed, 1);
        assert_eq!(parsed.cases[0].name, "file_test");
        assert!(parsed.cases[0].ok);
    }

    // HELP FUNCTIONALITY TESTS

    #[test]
    fn test_help_flag_long_form() -> Result<()> {
        // Test: template://--help
        let url = Url::parse("template://--help")?;
        let handle = TemplateHandle::from_url(url)?;

        assert!(handle.is_help_request);
        assert!(handle.help_verb.is_none());
        assert!(handle.template_path.is_none());

        let args = HashMap::new();
        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.call("dummy_verb", &args, &mut io)?;
        assert!(result.ok);
        assert_eq!(result.code, Some(0));

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        assert!(output.starts_with("Handle: template"));

        Ok(())
    }

    #[test]
    fn test_help_flag_short_form() -> Result<()> {
        // Test: template://-h
        let url = Url::parse("template://-h")?;
        let handle = TemplateHandle::from_url(url)?;

        assert!(handle.is_help_request);
        assert!(handle.help_verb.is_none());

        let args = HashMap::new();
        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.call("dummy_verb", &args, &mut io)?;
        assert!(result.ok);
        assert_eq!(result.code, Some(0));

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        assert!(output.starts_with("Handle: template"));

        Ok(())
    }

    #[test]
    fn test_help_contains_all_verbs() -> Result<()> {
        let url = Url::parse("template://--help")?;
        let handle = TemplateHandle::from_url(url)?;

        let args = HashMap::new();
        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        handle.call("dummy_verb", &args, &mut io)?;
        let output = String::from_utf8(stdout.into_inner()).unwrap();

        assert!(output.contains("render"));
        assert!(output.contains("validate"));
        assert!(output.contains("test"));

        Ok(())
    }

    #[test]
    fn test_help_contains_template_syntax() -> Result<()> {
        let url = Url::parse("template://--help")?;
        let handle = TemplateHandle::from_url(url)?;

        let args = HashMap::new();
        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        handle.call("dummy_verb", &args, &mut io)?;
        let output = String::from_utf8(stdout.into_inner()).unwrap();

        // Approved help describes the engine and the inline form
        assert!(output.contains("Tera"));
        assert!(output.contains("template://inline"));

        Ok(())
    }

    #[test]
    fn test_help_contains_examples() -> Result<()> {
        let url = Url::parse("template://--help")?;
        let handle = TemplateHandle::from_url(url)?;

        let args = HashMap::new();
        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        handle.call("dummy_verb", &args, &mut io)?;
        let output = String::from_utf8(stdout.into_inner()).unwrap();

        // Every verb is listed with its definition
        assert!(output.contains("render"));
        assert!(output.contains("validate"));
        assert!(output.contains("test"));
        assert!(output.contains("resh template://<path>|inline.<verb>"));

        Ok(())
    }

    #[test]
    fn test_help_contains_output_formats() -> Result<()> {
        let url = Url::parse("template://--help?help=render")?;
        let handle = TemplateHandle::from_url(url)?;

        let args = HashMap::new();
        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        handle.call("dummy_verb", &args, &mut io)?;
        let output = String::from_utf8(stdout.into_inner()).unwrap();

        assert!(output.contains("text"));
        assert!(output.contains("html"));
        assert!(output.contains("json"));
        assert!(output.contains("bytes"));

        Ok(())
    }

    #[test]
    fn test_verb_specific_help_render() -> Result<()> {
        // Test: template://--help?help=render
        let url = Url::parse("template://--help?help=render")?;
        let handle = TemplateHandle::from_url(url)?;

        assert!(handle.is_help_request);
        assert_eq!(handle.help_verb, Some("render".to_string()));

        let args = HashMap::new();
        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.call("dummy_verb", &args, &mut io)?;
        assert!(result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        assert!(output.starts_with("Handle: template"));
        assert!(output.contains("resh template://<path>.render"));

        Ok(())
    }

    #[test]
    fn test_verb_specific_help_validate() -> Result<()> {
        // Test: template://--help?help=validate
        let url = Url::parse("template://--help?help=validate")?;
        let handle = TemplateHandle::from_url(url)?;

        assert!(handle.is_help_request);
        assert_eq!(handle.help_verb, Some("validate".to_string()));

        let args = HashMap::new();
        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.call("dummy_verb", &args, &mut io)?;
        assert!(result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        assert!(output.starts_with("Handle: template"));
        assert!(output.contains("resh template://<path>.validate"));

        Ok(())
    }

    #[test]
    fn test_verb_specific_help_test() -> Result<()> {
        // Test: template://--help?help=test
        let url = Url::parse("template://--help?help=test")?;
        let handle = TemplateHandle::from_url(url)?;

        assert!(handle.is_help_request);
        assert_eq!(handle.help_verb, Some("test".to_string()));

        let args = HashMap::new();
        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.call("dummy_verb", &args, &mut io)?;
        assert!(result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        assert!(output.starts_with("Handle: template"));
        assert!(output.contains("resh template://<path>.test"));

        Ok(())
    }

    #[test]
    fn test_verb_specific_help_unknown_verb() -> Result<()> {
        // Test: template://--help?help=unknown
        let url = Url::parse("template://--help?help=unknown")?;
        let handle = TemplateHandle::from_url(url)?;

        assert!(handle.is_help_request);
        assert_eq!(handle.help_verb, Some("unknown".to_string()));

        let args = HashMap::new();
        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.call("dummy_verb", &args, &mut io)?;
        assert!(!result.ok);
        assert_eq!(result.code, Some(1));

        let output = String::from_utf8(stderr.into_inner()).unwrap();
        assert!(output.contains("Unknown verb: unknown"));

        Ok(())
    }

    #[test]
    fn test_help_from_url_detection() -> Result<()> {
        // Test various URL patterns that should trigger help
        let test_cases = vec![
            "template://--help",
            "template://-h",
            "template://myfile.html.--help",
            "template://inline.--help",
            "template:///path/to/file.txt.--help",
        ];

        for test_url in test_cases {
            let url = Url::parse(test_url)?;
            let handle = TemplateHandle::from_url(url)?;
            assert!(
                handle.is_help_request,
                "URL {} should trigger help",
                test_url
            );
        }

        Ok(())
    }

    #[test]
    fn test_non_help_from_url_detection() -> Result<()> {
        // Test URLs that should NOT trigger help
        let test_cases = vec![
            "template://myfile.html",
            "template://inline",
            "template:///path/to/file.txt",
            "template://dir/subdir/template.html",
        ];

        for test_url in test_cases {
            let url = Url::parse(test_url)?;
            let handle = TemplateHandle::from_url(url)?;
            assert!(
                !handle.is_help_request,
                "URL {} should NOT trigger help",
                test_url
            );
        }

        Ok(())
    }

    #[test]
    fn test_help_exit_code() -> Result<()> {
        let url = Url::parse("template://--help")?;
        let handle = TemplateHandle::from_url(url)?;

        let args = HashMap::new();
        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.call("dummy_verb", &args, &mut io)?;
        assert!(result.ok);
        assert_eq!(result.code, Some(0));

        Ok(())
    }

    #[test]
    fn test_help_output_format() -> Result<()> {
        let url = Url::parse("template://--help")?;
        let handle = TemplateHandle::from_url(url)?;

        let args = HashMap::new();
        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        handle.call("dummy_verb", &args, &mut io)?;
        let output = String::from_utf8(stdout.into_inner()).unwrap();

        // Check for the approved help sections
        assert!(output.starts_with("Handle: template"));
        assert!(output.contains("Description:"));
        assert!(output.contains("Available Verbs:"));
        assert!(output.contains("Usage:"));

        Ok(())
    }

    #[test]
    fn test_normal_operation_not_affected() -> Result<()> {
        // Test that normal operations still work when help is not requested
        let url = Url::parse("template://inline")?;
        let handle = TemplateHandle::from_url(url)?;

        assert!(!handle.is_help_request);
        assert!(handle.help_verb.is_none());

        // This should proceed to normal verb processing
        // (We won't test the full rendering here as that's covered by existing tests)

        Ok(())
    }

    // --- dispatch tests: every verb through Handle::call -------------------

    fn handle_for(url: &str) -> TemplateHandle {
        TemplateHandle::from_url(Url::parse(url).unwrap()).unwrap()
    }

    fn call(h: &TemplateHandle, verb: &str, kv: &[(&str, &str)]) -> (Status, serde_json::Value) {
        let args: Args = kv
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let (mut i, mut o, mut e) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut i,
            stdout: &mut o,
            stderr: &mut e,
        };
        let status = h.call(verb, &args, &mut io).unwrap();
        let out = String::from_utf8(o.into_inner()).unwrap();
        let json = serde_json::from_str(&out).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    fn inline() -> TemplateHandle {
        handle_for("template://inline")
    }

    /// A template file inside a fresh temp dir, named by its absolute path.
    fn file_template(dir: &TempDir, name: &str, text: &str) -> TemplateHandle {
        let path = dir.path().join(name);
        std::fs::write(&path, text).unwrap();
        TemplateHandle {
            template_path: Some(path),
            is_help_request: false,
            help_verb: None,
        }
    }

    fn first_error_kind(v: &serde_json::Value) -> String {
        v["errors"][0]["kind"].as_str().unwrap_or("").to_string()
    }

    const SLOW: &str = "{% for i in range(end=50000000) %}{{ i }}{% endfor %}";

    #[test]
    fn render_dispatch_success_and_formats() {
        let (s, v) = call(
            &inline(),
            "render",
            &[
                ("template", "Hello {{ name }}"),
                ("context", r#"{"name":"world"}"#),
            ],
        );
        assert!(s.ok);
        assert_eq!(v["body"]["value"], "Hello world");
        assert_eq!(v["template"]["source"], "inline");
        assert_eq!(v["context"]["keys"][0], "name");

        let (s, v) = call(&inline(), "render", &[("from", "x"), ("format", "html")]);
        assert!(s.ok);
        assert_eq!(v["body"]["type"], "html");

        let (s, v) = call(
            &inline(),
            "render",
            &[
                ("template", r#"{"port": {{ port }}}"#),
                ("context", r#"{"port":8080}"#),
                ("format", "json"),
            ],
        );
        assert!(s.ok);
        assert_eq!(v["body"]["value"]["port"], 8080);

        let (s, v) = call(
            &inline(),
            "render",
            &[("template", "hi"), ("format", "bytes")],
        );
        assert!(s.ok);
        assert_eq!(v["body"]["base64"], "aGk=");
    }

    #[test]
    fn render_error_paths() {
        // No template source.
        let (s, v) = call(&inline(), "render", &[]);
        assert_eq!(s.code, Some(2));
        assert_eq!(first_error_kind(&v), "template_not_found");
        // Missing file.
        let (s, v) = call(&handle_for("template://no-such-file.txt"), "render", &[]);
        assert_eq!(s.code, Some(1));
        assert_eq!(first_error_kind(&v), "template_not_found");
        // Bad context JSON, unreadable context_file, non-object context.
        let (s, v) = call(
            &inline(),
            "render",
            &[("template", "x"), ("context", "{bad")],
        );
        assert_eq!(
            (s.code, first_error_kind(&v).as_str()),
            (Some(1), "context_parse")
        );
        let (s, v) = call(
            &inline(),
            "render",
            &[("template", "x"), ("context_file", "/nonexistent/ctx.json")],
        );
        assert_eq!((s.code, first_error_kind(&v).as_str()), (Some(1), "io"));
        let (s, v) = call(
            &inline(),
            "render",
            &[("template", "x"), ("context", "[1]")],
        );
        assert_eq!(
            (s.code, first_error_kind(&v).as_str()),
            (Some(1), "context_parse")
        );
        // Syntax error and missing variable: the message names the cause.
        let (s, v) = call(&inline(), "render", &[("template", "{% if %}")]);
        assert_eq!((s.code, first_error_kind(&v).as_str()), (Some(1), "render"));
        let (s, v) = call(&inline(), "render", &[("template", "{{ who }}")]);
        assert_eq!((s.code, first_error_kind(&v).as_str()), (Some(1), "render"));
        let msg = v["errors"][0]["message"].as_str().unwrap();
        assert!(msg.contains("Variable `who` not found"), "{msg}");
        // Rendered text that is not JSON with format=json.
        let (s, v) = call(
            &inline(),
            "render",
            &[("template", "nope"), ("format", "json")],
        );
        assert_eq!(
            (s.code, first_error_kind(&v).as_str()),
            (Some(1), "json_parse")
        );
        assert!(v.get("body").is_none());
    }

    #[test]
    fn invalid_arguments_are_refused_before_reading() {
        // A missing template file is not reported: the arguments fail first.
        let h = handle_for("template://no-such-file.txt");
        let cases: &[(&str, &[(&str, &str)], &str)] = &[
            ("render", &[("format", "xml")], "invalid_format"),
            ("render", &[("timeout_ms", "soon")], "invalid_argument"),
            ("render", &[("strict", "true")], "invalid_argument"),
            ("validate", &[("strict", "ture")], "invalid_argument"),
            ("validate", &[("encoding", "latin1")], "encoding"),
            ("validate", &[("format", "json")], "invalid_argument"),
            ("validate", &[("timeout_ms", "-1")], "invalid_argument"),
        ];
        for (verb, kv, kind) in cases {
            let (s, v) = call(&h, verb, kv);
            assert_eq!(s.code, Some(2), "{verb} {kv:?}: {v}");
            assert_eq!(&first_error_kind(&v), kind, "{verb} {kv:?}: {v}");
            assert_eq!(v["ok"], false);
        }
        for kv in [
            &[("stop_on_first_fail", "yes please")][..],
            &[("capture_output", "everything")][..],
            &[("timeout_ms", "1s")][..],
            &[("context", "{}")][..],
        ] {
            let (s, v) = call(&h, "test", kv);
            assert_eq!(s.code, Some(2), "{kv:?}: {v}");
            assert_eq!(s.reason.as_deref(), Some("invalid_argument"));
            assert_eq!(v["ok"], false);
        }
    }

    #[test]
    fn unknown_verb_fails_with_exit_2() {
        let (s, _) = call(&inline(), "compile", &[]);
        assert_eq!(s.code, Some(2));
        assert!(s.reason.unwrap().contains("unknown verb: compile"));
    }

    #[test]
    fn render_timeout_is_enforced() {
        let started = std::time::Instant::now();
        let (s, v) = call(
            &inline(),
            "render",
            &[("template", SLOW), ("timeout_ms", "100")],
        );
        assert_eq!(s.code, Some(TIMEOUT_EXIT));
        assert_eq!(first_error_kind(&v), "timeout");
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        // A generous limit lets a quick render through; 0 means no limit.
        for t in ["10000", "0"] {
            let (s, v) = call(
                &inline(),
                "render",
                &[("template", "ok"), ("timeout_ms", t)],
            );
            assert!(s.ok);
            assert_eq!(v["body"]["value"], "ok");
        }
    }

    #[test]
    fn validate_timeout_is_enforced() {
        let (s, v) = call(
            &inline(),
            "validate",
            &[("template", SLOW), ("timeout_ms", "100")],
        );
        assert_eq!(s.code, Some(TIMEOUT_EXIT));
        assert_eq!(first_error_kind(&v), "timeout");
        let (s, _) = call(
            &inline(),
            "validate",
            &[("template", "ok"), ("timeout_ms", "10000")],
        );
        assert!(s.ok);
    }

    #[test]
    fn test_timeout_reports_cases_that_ran() {
        let cases = r#"[
            {"name":"quick","context":{"slow":false},"expected":"done"},
            {"name":"slow","context":{"slow":true},"expected":"done"}
        ]"#;
        let template =
            "{% if slow %}{% for i in range(end=50000000) %}{{ i }}{% endfor %}{% endif %}done";
        let (s, v) = call(
            &inline(),
            "test",
            &[
                ("template", template),
                ("cases", cases),
                ("timeout_ms", "300"),
            ],
        );
        assert_eq!(s.code, Some(TIMEOUT_EXIT), "{v}");
        assert_eq!(v["ok"], false);
        assert_eq!(v["total"], 1);
        assert_eq!(v["passed"], 1);
        assert_eq!(v["cases"][0]["name"], "quick");
        let error = v["error"].as_str().unwrap();
        assert!(
            error.contains("timeout_ms=300") && error.contains("1 of 2 cases ran"),
            "{error}"
        );
    }

    #[test]
    fn validate_reads_template_argument_and_context_file() {
        let dir = TempDir::new().unwrap();
        let ctx = dir.path().join("ctx.json");
        std::fs::write(&ctx, r#"{"name":"alice"}"#).unwrap();
        let ctx = ctx.to_str().unwrap();

        let (s, v) = call(
            &inline(),
            "validate",
            &[("template", "Hi {{ name }}"), ("context_file", ctx)],
        );
        assert!(s.ok, "{v}");
        assert_eq!(v["template"]["source"], "inline");
        assert_eq!(v["template"]["size"], 13);

        // `context` replaces `context_file` entirely.
        let (s, v) = call(
            &inline(),
            "validate",
            &[
                ("template", "Hi {{ name }}"),
                ("context_file", ctx),
                ("context", r#"{"other":1}"#),
            ],
        );
        assert_eq!(s.code, Some(1));
        assert_eq!(first_error_kind(&v), "missing_variable");

        let (s, v) = call(&inline(), "validate", &[("inline", "x")]);
        assert!(s.ok, "{v}");
        assert_eq!(v["template"]["source"], "inline");

        let (s, v) = call(
            &inline(),
            "validate",
            &[("template", "x"), ("context_file", "/nonexistent/ctx.json")],
        );
        assert_eq!(
            (s.code, first_error_kind(&v).as_str()),
            (Some(1), "file_read")
        );
    }

    #[test]
    fn validate_error_paths() {
        let (s, v) = call(&inline(), "validate", &[]);
        assert_eq!(
            (s.code, first_error_kind(&v).as_str()),
            (Some(2), "file_read")
        );
        let (s, v) = call(&handle_for("template://no-such-file.txt"), "validate", &[]);
        assert_eq!(
            (s.code, first_error_kind(&v).as_str()),
            (Some(1), "file_read")
        );
        let (s, v) = call(&inline(), "validate", &[("from", "x"), ("context", "{bad")]);
        assert_eq!(
            (s.code, first_error_kind(&v).as_str()),
            (Some(1), "context_parse")
        );
        let (s, v) = call(&inline(), "validate", &[("from", "{% for %}")]);
        assert_eq!((s.code, first_error_kind(&v).as_str()), (Some(1), "syntax"));
        let (s, v) = call(
            &inline(),
            "validate",
            &[
                ("from", "{{ x | no_such_filter }}"),
                ("context", r#"{"x":1}"#),
            ],
        );
        assert_eq!(s.code, Some(1));
        assert!(
            ["syntax", "render"].contains(&first_error_kind(&v).as_str()),
            "{v}"
        );
        let (s, v) = call(
            &inline(),
            "validate",
            &[("from", "{{ x | round }}"), ("context", r#"{"x":"text"}"#)],
        );
        assert_eq!((s.code, first_error_kind(&v).as_str()), (Some(1), "render"));
    }

    #[test]
    fn validate_strict_spellings() {
        for (value, ok) in [
            ("false", true),
            ("0", true),
            ("no", true),
            ("true", false),
            ("YES", false),
        ] {
            let (s, v) = call(
                &inline(),
                "validate",
                &[("from", "{{ x }}"), ("strict", value)],
            );
            assert_eq!(s.ok, ok, "strict={value}: {v}");
            assert_eq!(v["strict"], !ok);
            let list = if ok { "warnings" } else { "errors" };
            assert_eq!(v[list][0]["kind"], "missing_variable", "{v}");
        }
    }

    #[test]
    fn test_dispatch_cases_file_default_file_and_options() {
        let dir = TempDir::new().unwrap();
        let h = file_template(&dir, "welcome.txt", "Hello, {{ name }}!");
        std::fs::write(
            dir.path().join("welcome.tests.json"),
            r#"[{"name":"alice","context":{"name":"alice"},"expected":"Hello, alice!"}]"#,
        )
        .unwrap();
        let (s, v) = call(&h, "test", &[]);
        assert!(s.ok, "{v}");
        assert_eq!(v["total"], 1);

        let cases = dir.path().join("cases.json");
        std::fs::write(
            &cases,
            r#"[{"name":"a","context":{"name":"a"},"contains":"a!"},
                {"name":"b","context":{"name":"b"},"expected":"nope"},
                {"name":"c","context":{"name":"c"},"not_contains":"c"}]"#,
        )
        .unwrap();
        let cases = cases.to_str().unwrap();
        let (s, v) = call(
            &h,
            "test",
            &[("cases_file", cases), ("capture_output", "full")],
        );
        assert_eq!(s.code, Some(1));
        assert_eq!(
            (v["passed"].as_u64(), v["failed"].as_u64()),
            (Some(1), Some(2))
        );
        assert_eq!(v["cases"][0]["rendered"], "Hello, a!");
        let (s, v) = call(
            &h,
            "test",
            &[
                ("cases_file", cases),
                ("stop_on_first_fail", "true"),
                ("capture_output", "none"),
            ],
        );
        assert_eq!(s.code, Some(1));
        assert_eq!(v["total"], 2);
        assert!(v["cases"][1].get("rendered").is_none());
    }

    #[test]
    fn test_error_paths() {
        let dir = TempDir::new().unwrap();
        let h = file_template(&dir, "t.txt", "x");
        let (s, v) = call(&h, "test", &[]);
        assert_eq!(
            (s.code, s.reason.as_deref()),
            (Some(2), Some("no_test_cases"))
        );
        assert!(v["error"].as_str().unwrap().contains("no test cases"));
        let (s, _) = call(
            &handle_for("template://no-such-file.txt"),
            "test",
            &[("cases", "[]")],
        );
        assert_eq!(
            (s.code, s.reason.as_deref()),
            (Some(1), Some("template_not_found"))
        );
        let (s, _) = call(&h, "test", &[("cases", "[")]);
        assert_eq!(
            (s.code, s.reason.as_deref()),
            (Some(2), Some("no_test_cases"))
        );
        let (s, _) = call(&h, "test", &[("cases_file", "/nonexistent/cases.json")]);
        assert_eq!(
            (s.code, s.reason.as_deref()),
            (Some(1), Some("no_test_cases"))
        );
        let (s, _) = call(&h, "test", &[("cases", "[]")]);
        assert_eq!(
            (s.code, s.reason.as_deref()),
            (Some(1), Some("no_test_cases"))
        );
        let (s, _) = call(
            &inline(),
            "test",
            &[
                ("template", "{% if %}"),
                ("cases", r#"[{"name":"a","context":{}}]"#),
            ],
        );
        assert_eq!(
            (s.code, s.reason.as_deref()),
            (Some(1), Some("tera_parse_failed"))
        );
        let (s, v) = call(
            &inline(),
            "test",
            &[
                ("template", "{{ y }}"),
                ("cases", r#"[{"name":"a","context":{}}]"#),
            ],
        );
        assert_eq!(s.code, Some(1));
        assert!(
            v["cases"][0]["error"]
                .as_str()
                .unwrap()
                .contains("Variable `y` not found")
        );
        let (s, v) = call(
            &inline(),
            "test",
            &[
                ("template", "x"),
                ("cases", r#"[{"name":"a","context":[1]}]"#),
            ],
        );
        assert_eq!(s.code, Some(1));
        assert!(
            v["cases"][0]["error"]
                .as_str()
                .unwrap()
                .contains("failed to convert context")
        );
    }

    #[test]
    fn unknown_argument_suggests_the_closest_name() {
        let (s, v) = call(&inline(), "render", &[("template", "x"), ("contxt", "{}")]);
        assert_eq!(s.code, Some(2));
        let msg = v["errors"][0]["message"].as_str().unwrap();
        assert!(msg.contains("did you mean `context`?"), "{msg}");
        let (_, v) = call(&inline(), "test", &[("Timeout-MS", "5")]);
        assert!(
            v["error"]
                .as_str()
                .unwrap()
                .contains("did you mean `timeout_ms`?")
        );
        let (_, v) = call(&inline(), "render", &[("zzzzzz", "1")]);
        assert!(
            !v["errors"][0]["message"]
                .as_str()
                .unwrap()
                .contains("did you mean")
        );
        assert_eq!(suggest("stirct", VALIDATE_ARGS), Some("strict"));
    }

    const RECURSE_FOREVER: &str =
        "{% macro m(n) %}{{ self::m(n=n+1) }}{% endmacro m %}{{ self::m(n=1) }}";

    #[test]
    fn unbounded_macro_recursion_is_a_render_error_not_an_abort() {
        for verb in ["render", "validate"] {
            let (s, v) = call(&inline(), verb, &[("template", RECURSE_FOREVER)]);
            assert_eq!(s.code, Some(1), "{verb}: {v}");
            let msg = v["errors"][0]["message"].as_str().unwrap();
            assert!(msg.contains("nested deeper than 200 levels"), "{msg}");
        }
        // Mutual recursion, and recursion through set, for and filter args.
        let mutual = "{% macro a(n) %}{{ self::b(n=n) }}{% endmacro a %}\
            {% macro b(n) %}{% for i in [1] %}{% set x = self::a(n=n) %}{{ x }}{% endfor %}{% endmacro b %}\
            {{ self::a(n=1) }}";
        let (s, v) = call(&inline(), "render", &[("template", mutual)]);
        assert_eq!(s.code, Some(1), "{v}");
        let (s, v) = call(
            &inline(),
            "test",
            &[
                ("template", RECURSE_FOREVER),
                ("cases", r#"[{"name":"a","context":{}}]"#),
            ],
        );
        assert_eq!(s.code, Some(1));
        assert!(
            v["cases"][0]["error"]
                .as_str()
                .unwrap()
                .contains("nested deeper")
        );
    }

    #[test]
    fn bounded_macro_recursion_still_works() {
        let countdown = "{% macro c(n) %}{% if n > 0 %}{{ n }} {{ self::c(n=n-1) }}{% endif %}\
            {% endmacro c %}{{ self::c(n=3) }}|{{ self::c(n=199) | length > 0 }}";
        let (s, v) = call(&inline(), "render", &[("template", countdown)]);
        assert!(s.ok, "{v}");
        assert!(
            v["body"]["value"].as_str().unwrap().starts_with("3 2 1 "),
            "{v}"
        );
        // Macro defaults and explicit arguments are untouched.
        let defaults = "{% macro g(who=\"you\") %}hi {{ who }}{% endmacro g %}\
            {{ self::g() }}/{{ self::g(who=\"me\") }}";
        let (s, v) = call(&inline(), "render", &[("template", defaults)]);
        assert!(s.ok, "{v}");
        assert_eq!(v["body"]["value"], "hi you/hi me");
    }

    #[test]
    fn leading_parent_dir_is_kept() {
        assert_eq!(
            normalize_path(&PathBuf::from("../x.txt")),
            PathBuf::from("../x.txt")
        );
        assert_eq!(
            normalize_path(&PathBuf::from("a/../x.txt")),
            PathBuf::from("x.txt")
        );
        assert_eq!(
            normalize_path(&PathBuf::from("a/../../x.txt")),
            PathBuf::from("../x.txt")
        );
        assert_eq!(
            normalize_path(&PathBuf::from("./a/./b")),
            PathBuf::from("a/b")
        );
    }

    #[test]
    fn verb_args_match_help_usage() {
        for verb in TEMPLATE_HELP.verbs {
            let usage = verb.detail.as_ref().unwrap().usage;
            let mut in_usage: Vec<&str> = usage
                .split(|c: char| c == '[' || c.is_whitespace())
                .filter_map(|w| w.split_once('=').map(|(k, _)| k))
                .collect();
            in_usage.sort();
            let mut parsed = verb_args(verb.name).unwrap().to_vec();
            parsed.sort();
            assert_eq!(
                in_usage, parsed,
                "usage of {} disagrees with its arguments",
                verb.name
            );
        }
    }
}
