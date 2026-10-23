#![cfg(feature = "cli")]

use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    process::{Child, ChildStdin, Command, ExitStatus, Stdio},
    sync::mpsc::{self, Receiver},
    thread,
    time::{Duration, Instant},
};

struct Helper {
    child: Child,
    input: Option<ChildStdin>,
    responses: Receiver<String>,
    reader: Option<thread::JoinHandle<()>>,
    next_id: u64,
}
impl Helper {
    fn start(directory: &Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_beagle"))
            .arg("helper-stdio")
            .current_dir(directory)
            .env_remove("GRAPHQLITE_EXTENSION")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let (sender, responses) = mpsc::channel();
        let reader = thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if sender.send(line.unwrap()).is_err() {
                    return;
                }
            }
        });
        let helper = Self {
            child,
            input,
            responses,
            reader: Some(reader),
            next_id: 1,
        };
        let ready = helper.read();
        assert_eq!(ready["type"], "ready");
        assert_eq!(ready["protocol"], 1);
        assert_eq!(ready["name"], "beagle");
        assert_eq!(ready["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(
            ready["limits"],
            json!({"requestBytes":1_048_576,"responseBytes":33_554_432})
        );
        assert_eq!(ready["operations"].as_array().unwrap().len(), 14);
        helper
    }
    fn read(&self) -> Value {
        let line = self
            .responses
            .recv_timeout(Duration::from_secs(20))
            .expect("helper must flush a reply without waiting for EOF");
        assert!(line.len() < 33_554_432);
        serde_json::from_str(&line).expect("stdout must contain only JSON protocol frames")
    }
    fn request(&mut self, command: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let input = self.input.as_mut().unwrap();
        serde_json::to_writer(&mut *input, &json!({"id":id,"command":command})).unwrap();
        input.write_all(b"\n").unwrap();
        input.flush().unwrap();
        let response = self.read();
        assert_eq!(response["type"], "response");
        assert_eq!(response["id"], id);
        response
    }
    fn success(&mut self, command: Value) -> Value {
        let response = self.request(command);
        assert_eq!(response["ok"], true, "{response}");
        response["value"].clone()
    }
    fn finish(mut self, success: bool) -> String {
        self.input.take();
        let status = wait(&mut self.child);
        assert_eq!(status.success(), success);
        let mut stderr = String::new();
        self.child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        if success {
            assert!(stderr.is_empty(), "{stderr}");
        }
        self.reader.take().unwrap().join().unwrap();
        assert!(
            self.responses.try_recv().is_err(),
            "unexpected extra helper frame"
        );
        stderr
    }
}
impl Drop for Helper {
    fn drop(&mut self) {
        self.input.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}
fn wait(child: &mut Child) -> ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "helper must terminate after shutdown, EOF or fatal input"
        );
        thread::sleep(Duration::from_millis(10));
    }
}
fn open(database: &Path) -> Value {
    json!({"type":"open","database":database,"queryTimeoutMs":30000})
}

#[test]
fn persistent_workflow_and_restart_preserve_database_state() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("graph.db");
    let users = temp.path().join("users.json");
    let groups = temp.path().join("groups.json");
    fs::write(
        &users,
        json!({"meta":{"type":"users","version":6,"count":1},"data":[{
            "ObjectIdentifier":"USER","Properties":{"name":"ALICE@LAB.LOCAL","enabled":true}
        }]})
        .to_string(),
    )
    .unwrap();
    fs::write(
        &groups,
        json!({"meta":{"type":"groups","version":6,"count":1},"data":[{
            "ObjectIdentifier":"GROUP","Properties":{"name":"TEAM@LAB.LOCAL"},
            "Members":[{"ObjectIdentifier":"USER","ObjectType":"User"}]
        }]})
        .to_string(),
    )
    .unwrap();
    let mut helper = Helper::start(temp.path());
    assert!(!temp.path().join("beagle.db").exists());
    assert_eq!(
        helper.request(json!({"type":"stats"}))["error"]["code"],
        "database_not_open"
    );
    assert!(helper.success(open(&db)).is_null());
    assert_eq!(
        helper.request(open(&temp.path().join("other.db")))["error"]["code"],
        "database_already_open"
    );
    assert!(!temp.path().join("other.db").exists());
    let report = helper.success(json!({"type":"ingest","paths":[users,groups],"analyze":true}));
    assert_eq!(report["ingest"]["records"], 2);
    assert_eq!(helper.success(json!({"type":"stats"}))["nodes"], 2);
    assert_eq!(
        helper.success(json!({"type":"entity","objectid":"USER"}))["rows"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        helper.success(
            json!({"type":"paths","source":"USER","target":"GROUP","all":false,"maxHops":3})
        )["rows"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        helper
            .success(json!({"type":"compose","source":"USER","target":"GROUP","kind":"MemberOf"}))
            ["edges"]
            .as_array()
            .unwrap()
            .len(),
        0 // A direct MemberOf edge has no derived-edge explanation.
    );
    helper.success(json!({"type":"tag","objectid":"USER","tag":"owned","enabled":true}));
    helper.success(json!({"type":"analyze"}));
    let query = json!({"type":"query","cypher":"MATCH (u:Tag_Owned) RETURN u.objectid AS id","parameters":{}});
    assert_eq!(
        helper.success(query.clone())["rows"],
        json!([{"id":"USER"}])
    );
    let snapshot = helper.success(json!({"type":"export"}));
    assert_eq!(snapshot["nodes"].as_array().unwrap().len(), 2);
    assert!(helper.success(json!({"type":"shutdown"})).is_null());
    helper.finish(true);
    let mut restarted = Helper::start(temp.path());
    restarted.success(open(&db));
    assert_eq!(restarted.success(json!({"type":"export"})), snapshot);
    assert_eq!(restarted.success(query)["rows"], json!([{"id":"USER"}]));
    // EOF is a clean close, with no extra frame and no lingering database owner.
    restarted.finish(true);
    assert_eq!(
        beagle::Beagle::open(&db).unwrap().stats().unwrap()["nodes"],
        2
    );
}

#[test]
fn catalog_returns_authoritative_metadata_before_open_and_saved_queries_execute() {
    let temp = tempfile::tempdir().unwrap();
    let mut helper = Helper::start(temp.path());
    let catalog = helper.success(json!({"type":"catalog"}));
    let expected: Vec<_> = beagle::Beagle::query_catalog()
        .iter()
        .map(|entry| beagle::Beagle::saved_query(entry["guid"].as_str().unwrap()).unwrap())
        .collect();
    assert_eq!(catalog, json!(expected));
    assert_eq!(catalog.as_array().unwrap().len(), 177);
    let id = catalog[0]["guid"].as_str().unwrap();
    assert_eq!(
        helper.success(json!({"type":"savedQueryInfo","id":id})),
        catalog[0]
    );
    assert!(!temp.path().join("beagle.db").exists());
    helper.success(json!({"type":"open","database":":memory:","queryTimeoutMs":30000}));
    let result = helper.success(json!({"type":"savedQuery","id":id,"parameters":{}}));
    assert!(result["columns"].is_array());
    assert!(result["rows"].is_array());
    helper.finish(true);
}

#[test]
fn operation_failures_are_sanitized_and_do_not_break_the_session() {
    let temp = tempfile::tempdir().unwrap();
    let mut helper = Helper::start(temp.path());
    for command in [
        json!({"type":"open","database":"relative.db","queryTimeoutMs":30000}),
        json!({"type":"open","database":":memory:","queryTimeoutMs":0}),
        json!({"type":"open","database":":memory:","queryTimeoutMs":120001}),
        json!({"type":"query","cypher":" ","parameters":{}}),
        json!({"type":"paths","source":"a","target":"b","all":false,"maxHops":65}),
        json!({"type":"ingest","paths":[],"analyze":true}),
        json!({"type":"ingest","paths":["relative.json"],"analyze":true}),
        json!({"type":"entity","objectid":"x".repeat(513)}),
        json!({"type":"query","cypher":"RETURN $x","parameters":{"x":"x".repeat(65_536)}}),
    ] {
        assert_eq!(helper.request(command)["error"]["code"], "invalid_input");
    }
    let marker = "private-marker-DO-NOT-PRINT";
    let failed_open = helper.request(open(&temp.path().join(marker).join("unavailable.db")));
    assert_eq!(failed_open["error"]["code"], "operation_failed");
    assert!(!failed_open.to_string().contains(marker));
    helper.success(json!({"type":"open","database":":memory:","queryTimeoutMs":30000}));
    for command in [
        json!({"type":"query","cypher":format!("{marker} IS INVALID CYPHER"),"parameters":{}}),
        json!({"type":"savedQueryInfo","id":marker}),
        json!({"type":"query","cypher":"CREATE (n:Unwanted) RETURN n","parameters":{}}),
    ] {
        let error = helper.request(command);
        assert_eq!(error["error"]["code"], "operation_failed");
        assert!(!error.to_string().contains(marker));
    }
    let hostile = "'; --db=/somewhere $(echo no)";
    assert_eq!(
        helper
            .success(json!({"type":"query","cypher":"RETURN $x AS x","parameters":{"x":hostile}}))
            ["rows"],
        json!([{"x":hostile}])
    );
    assert_eq!(helper.success(json!({"type":"stats"}))["nodes"], 0);
    helper.finish(true);
}

#[test]
fn oversized_response_is_replaced_atomically_and_session_continues() {
    let temp = tempfile::tempdir().unwrap();
    let mut helper = Helper::start(temp.path());
    helper.success(json!({"type":"open","database":":memory:","queryTimeoutMs":30000}));
    // A modest bound parameter produces a response above the actual wire limit.
    let cypher = format!(
        "RETURN {}",
        (0..600)
            .map(|index| format!("$payload AS column{index}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    let response = helper.request(
        json!({"type":"query","cypher":cypher,"parameters":{"payload":"x".repeat(60_000)}}),
    );
    assert_eq!(response["ok"], false);
    assert_eq!(response["error"]["code"], "response_too_large");
    assert!(response.to_string().len() < 512);
    assert_eq!(
        helper.success(json!({"type":"query","cypher":"RETURN 42 AS answer","parameters":{}}))["rows"],
        json!([{"answer":42}])
    );
    helper.finish(true);
}

fn fatal_input(bytes: &[u8], expected_code: &str) {
    let temp = tempfile::tempdir().unwrap();
    let mut helper = Helper::start(temp.path());
    // An oversized producer can encounter BrokenPipe once the helper rejects it.
    let _ = helper.input.as_mut().unwrap().write_all(bytes);
    helper.input.take();
    let fatal = helper.read();
    assert_eq!(fatal["type"], "fatal");
    assert_eq!(fatal["error"]["code"], expected_code);
    assert!(!fatal.to_string().contains("DO-NOT-PRINT"));
    assert!(!helper.finish(false).contains("DO-NOT-PRINT"));
    assert!(!temp.path().join("beagle.db").exists());
}

#[test]
fn malformed_envelopes_and_unknown_fields_fail_closed() {
    for text in [
        "DO-NOT-PRINT\n",
        "{\"id\":1,\"command\":{\"type\":\"DO-NOT-PRINT\"}}\n",
        "{\"id\":1,\"command\":{\"type\":\"stats\",\"extra\":true}}\n",
        "{\"id\":1,\"command\":{\"type\":\"stats\"},\"extra\":true}\n",
        "{\"id\":1,\"id\":2,\"command\":{\"type\":\"stats\"}}\n",
        "{\"id\":1,\"command\":{\"type\":\"query\",\"cypher\":\"RETURN 1\",\"parameters\":null}}\n",
        "{\"id\":1,\"command\":{\"type\":\"tag\",\"objectid\":\"a\",\"tag\":\"invalid\",\"enabled\":true}}\n",
        "{\"id\":1.5,\"command\":{\"type\":\"stats\"}}\n",
        "{\"id\":-1,\"command\":{\"type\":\"stats\"}}\n",
        "{}\n",
        "\n",
    ] {
        fatal_input(text.as_bytes(), "invalid_request");
    }
    fatal_input(b"\xff\n", "invalid_request");
    fatal_input(
        b"{\"id\":0,\"command\":{\"type\":\"stats\"}}\n",
        "invalid_request_id",
    );
    fatal_input(
        b"{\"id\":9007199254740992,\"command\":{\"type\":\"stats\"}}\n",
        "invalid_request_id",
    );
}

#[test]
fn duplicate_and_reordered_ids_terminate_after_prior_response() {
    for id in [1, 2] {
        let temp = tempfile::tempdir().unwrap();
        let mut helper = Helper::start(temp.path());
        helper.next_id = 2;
        helper
            .success(json!({"type":"savedQueryInfo","id":"c902d3b4-1a75-4335-acd7-28246dab746d"}));
        writeln!(
            helper.input.as_mut().unwrap(),
            "{}",
            json!({"id":id,"command":{"type":"stats"}})
        )
        .unwrap();
        assert_eq!(helper.read()["error"]["code"], "invalid_request_id");
        helper.finish(false);
    }
}

#[test]
fn bounded_lines_accept_exact_limit_and_reject_overflow_or_truncation() {
    let temp = tempfile::tempdir().unwrap();
    let mut helper = Helper::start(temp.path());
    let mut exact = br#"{"id":1,"command":{"type":"savedQueryInfo","id":"c902d3b4-1a75-4335-acd7-28246dab746d"}}"#.to_vec();
    exact.resize(1_048_575, b' ');
    exact.push(b'\n');
    helper.input.as_mut().unwrap().write_all(&exact).unwrap();
    assert_eq!(helper.read()["ok"], true);
    helper.finish(true);
    let mut overflow = vec![b' '; 1_048_576];
    overflow.push(b'\n');
    fatal_input(&overflow, "request_too_large");
    fatal_input(
        br#"{"id":1,"command":{"type":"stats"}}"#,
        "truncated_request",
    );
    fatal_input(b"DO-NOT-PRINT", "truncated_request");
}

#[test]
fn legacy_cli_and_serve_stdio_keep_their_original_protocol() {
    let temp = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_beagle"))
        .args(["--db", ":memory:", "query", "RETURN 42 AS answer"])
        .current_dir(temp.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["rows"],
        json!([{"answer":42}])
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_beagle"))
        .args(["--db", ":memory:", "serve-stdio"])
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"{\"op\":\"query\",\"query\":\"RETURN 7 AS answer\"}\n{\"op\":\"stats\"}\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let lines: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["value"]["rows"], json!([{"answer":7}]));
    assert_eq!(lines[1]["value"]["nodes"], 0);
    assert!(lines.iter().all(|line| line.get("type").is_none()));
}
