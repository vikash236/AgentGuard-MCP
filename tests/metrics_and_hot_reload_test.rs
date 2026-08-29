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
async fn test_gateway_metrics_endpoint() {
    let mock_port = 3199;
    let gateway_port = 8189;

    tokio::spawn(async move {
        mock_target_server(mock_port).await;
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

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

    let mut child = Command::new(exe_path)
        .args([
            "gateway",
            "--port",
            &gateway_port.to_string(),
            "--target",
            &format!("http://127.0.0.1:{mock_port}"),
            "--metrics",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start agentguard gateway with metrics");

    tokio::time::sleep(Duration::from_millis(500)).await;

    let client = reqwest::Client::new();
    let msg_url = format!("http://127.0.0.1:{gateway_port}/message");
    let metrics_url = format!("http://127.0.0.1:{gateway_port}/metrics");

    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "ping"
    });

    let resp = client.post(&msg_url).json(&payload).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let metrics_resp = client.get(&metrics_url).send().await.unwrap();
    assert_eq!(metrics_resp.status(), reqwest::StatusCode::OK);

    let body = metrics_resp.text().await.unwrap();
    assert!(body.contains("agentguard_requests_intercepted_total 1"));

    let _ = child.kill();
    let _ = child.wait();
}
