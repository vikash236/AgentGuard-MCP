use axum::{
    Json, Router,
    routing::{get, post},
};
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::net::TcpListener;

async fn mock_target_server(port: u16) {
    let app = Router::new()
        .route("/sse", get(|| async { "event: message\ndata: {}\n\n" }))
        .route(
            "/message",
            post(|Json(payload): Json<serde_json::Value>| async move {
                Json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": payload.get("id").unwrap_or(&serde_json::Value::Null),
                    "result": {"status": "ok_from_target"}
                }))
            }),
        );

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[tokio::test]
async fn test_gateway_auth_and_rate_limit() {
    let mock_port = 3099;
    let gateway_port = 8089;

    // Start mock target server
    tokio::spawn(async move {
        mock_target_server(mock_port).await;
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Build binary
    let build_status = Command::new("cargo")
        .args(["build", "--bin", "agentguard"])
        .status()
        .expect("Failed to build agentguard binary");
    assert!(build_status.success());

    let exe_path = if cfg!(windows) {
        "target/debug/agentguard.exe"
    } else {
        "target/debug/agentguard"
    };

    // Launch gateway proxy with token and rate limit 2 req/min
    let mut child = Command::new(exe_path)
        .args([
            "gateway",
            "--port",
            &gateway_port.to_string(),
            "--target",
            &format!("http://127.0.0.1:{mock_port}"),
            "--token",
            "secrettoken123",
            "--rate-limit",
            "2",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start agentguard gateway");

    tokio::time::sleep(Duration::from_millis(500)).await;

    let client = reqwest::Client::new();
    let msg_url = format!("http://127.0.0.1:{gateway_port}/message");

    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "ping"
    });

    // Test 1: Missing Bearer Token -> 401 Unauthorized
    let resp1 = client.post(&msg_url).json(&payload).send().await.unwrap();
    assert_eq!(resp1.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Test 2: Valid Bearer Token (1st request) -> 200 OK
    let resp2 = client
        .post(&msg_url)
        .header("Authorization", "Bearer secrettoken123")
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp2.status(), reqwest::StatusCode::OK);
    let body2: serde_json::Value = resp2.json().await.unwrap();
    assert_eq!(body2["result"]["status"], "ok_from_target");

    // Test 3: Valid Bearer Token (2nd request) -> 200 OK
    let resp3 = client
        .post(&msg_url)
        .header("Authorization", "Bearer secrettoken123")
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp3.status(), reqwest::StatusCode::OK);

    // Test 4: Exceed Rate Limit (3rd request) -> 429 Too Many Requests
    let resp4 = client
        .post(&msg_url)
        .header("Authorization", "Bearer secrettoken123")
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp4.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);

    let _ = child.kill();
    let _ = child.wait();
}
