use crate::audit_logger::AuditLogger;
use agentguard_jail::PathJail;
use agentguard_redactor::SecretRedactor;
use axum::{
    body::Body,
    extract::{Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use futures_util::StreamExt;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;

/// Configuration options for the HTTP/SSE Gateway Proxy.
pub struct GatewayConfig {
    pub port: u16,
    pub target_url: String,
    pub token: Option<String>,
    pub rate_limit: Option<u32>,
    pub jail: Option<PathJail>,
    pub redactor: Option<Arc<SecretRedactor>>,
    pub audit_logger: Arc<AuditLogger>,
}

#[derive(Clone)]
struct RateLimiter {
    max_req_per_min: u32,
    clients: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
}

impl RateLimiter {
    fn new(max_req_per_min: u32) -> Self {
        Self {
            max_req_per_min,
            clients: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn check_and_record(&self, client_id: &str) -> bool {
        let mut clients = self.clients.lock().unwrap();
        let now = Instant::now();
        let window_start = now.checked_sub(Duration::from_secs(60)).unwrap_or(now);

        let timestamps = clients.entry(client_id.to_string()).or_default();
        timestamps.retain(|&t| t > window_start);

        if timestamps.len() as u32 >= self.max_req_per_min {
            false
        } else {
            timestamps.push(now);
            true
        }
    }
}

#[derive(Clone)]
struct AppState {
    target_url: String,
    token: Option<String>,
    rate_limiter: Option<RateLimiter>,
    jail: Option<Arc<PathJail>>,
    redactor: Option<Arc<SecretRedactor>>,
    audit_logger: Arc<AuditLogger>,
    client: reqwest::Client,
}

/// Run the HTTP/SSE Gateway Proxy server.
pub async fn run_gateway(config: GatewayConfig) -> Result<(), Box<dyn std::error::Error>> {
    let jail_arc = config.jail.map(Arc::new);
    let rate_limiter = config.rate_limit.map(RateLimiter::new);

    let state = AppState {
        target_url: config.target_url.trim_end_matches('/').to_string(),
        token: config.token,
        rate_limiter,
        jail: jail_arc.clone(),
        redactor: config.redactor.clone(),
        audit_logger: config.audit_logger,
        client: reqwest::Client::builder().build()?,
    };

    eprintln!(
        "[agentguard] HTTP/SSE Gateway Proxy starting on port {}",
        config.port
    );
    eprintln!("[agentguard] Target remote MCP server: {}", state.target_url);

    if state.token.is_some() {
        eprintln!("[agentguard] Bearer Token authentication REQUIRED");
    }
    if let Some(limit) = config.rate_limit {
        eprintln!("[agentguard] Rate Limiting ACTIVE: max {limit} req/min");
    }
    if let Some(ref j) = jail_arc {
        eprintln!(
            "[agentguard] Path Jail ACTIVE. Root: '{}'",
            j.root().display()
        );
    }
    if state.redactor.is_some() {
        eprintln!("[agentguard] Secret Redactor ACTIVE");
    }

    let app = Router::new()
        .route("/", get(health_handler))
        .route("/sse", get(sse_handler))
        .route("/message", post(message_handler))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "AgentGuard-MCP HTTP/SSE Gateway Proxy"
    }))
}

async fn check_auth_and_rate(
    headers: &HeaderMap,
    state: &AppState,
    path: &str,
) -> Result<String, (StatusCode, &'static str)> {
    // 1. Bearer Token Auth
    if let Some(ref required_token) = state.token {
        let auth_header = headers
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok());

        let expected_auth = format!("Bearer {required_token}");
        if auth_header != Some(&expected_auth) {
            eprintln!("[agentguard-gateway] REJECTED unauthorized request to {path}");
            state.audit_logger.log_event(
                "unauthorized_access",
                "HIGH",
                &format!("REJECTED unauthorized request to {path}"),
            );
            return Err((
                StatusCode::UNAUTHORIZED,
                "401 Unauthorized: Invalid or missing Bearer token",
            ));
        }
    }

    // 2. Rate Limiter
    let client_id = headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("client_default");

    if state
        .rate_limiter
        .as_ref()
        .is_some_and(|limiter| !limiter.check_and_record(client_id))
    {
        eprintln!("[agentguard-gateway] RATE LIMITED client '{client_id}' on {path}");
        state.audit_logger.log_event(
            "rate_limit_exceeded",
            "MEDIUM",
            &format!("RATE LIMITED client '{client_id}' on {path}"),
        );
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "429 Too Many Requests: Rate limit exceeded",
        ));
    }

    Ok(client_id.to_string())
}

async fn sse_handler(
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    State(state): State<AppState>,
) -> Result<Response, (StatusCode, &'static str)> {
    check_auth_and_rate(&headers, &state, "/sse").await?;

    let mut target_sse_url = format!("{}/sse", state.target_url);
    if !params.is_empty() {
        let query_string: Vec<String> = params.iter().map(|(k, v)| format!("{k}={v}")).collect();
        target_sse_url.push('?');
        target_sse_url.push_str(&query_string.join("&"));
    }

    let mut req_builder = state.client.get(&target_sse_url);
    if let Some(ref token) = state.token {
        req_builder = req_builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }

    let resp = match req_builder.send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[agentguard-gateway] Error connecting to target SSE endpoint: {e}");
            return Err((StatusCode::BAD_GATEWAY, "502 Bad Gateway"));
        }
    };

    let stream = resp.bytes_stream();
    let redactor_opt = state.redactor.clone();
    let logger_clone = state.audit_logger.clone();

    let mapped_stream = stream.map(move |chunk_result| match chunk_result {
        Ok(bytes) => {
            if let Some(ref redactor) = redactor_opt {
                let text = String::from_utf8_lossy(&bytes);
                let (redacted_text, count) = redactor.redact_text(&text);
                if count > 0 {
                    eprintln!("[agentguard-redactor] REDACTED {count} secret(s) in SSE event stream");
                    logger_clone.log_event(
                        "secret_redaction",
                        "MEDIUM",
                        &format!("REDACTED {count} secret(s) in SSE event stream"),
                    );
                    Ok(axum::body::Bytes::from(redacted_text))
                } else {
                    Ok(bytes)
                }
            } else {
                Ok(bytes)
            }
        }
        Err(e) => Err(std::io::Error::other(e)),
    });

    let mut response = Response::new(Body::from_stream(mapped_stream));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache"),
    );
    Ok(response)
}

async fn message_handler(
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Response, (StatusCode, &'static str)> {
    check_auth_and_rate(&headers, &state, "/message").await?;

    // 1. Path Jail Inspection for tools/call
    if let Some(err_resp) = state
        .jail
        .as_ref()
        .and_then(|jail| inspect_http_payload(jail, &payload, &state.audit_logger))
    {
        return Ok((StatusCode::OK, Json(err_resp)).into_response());
    }

    // 2. Forward payload to target server
    let mut target_msg_url = format!("{}/message", state.target_url);
    if !params.is_empty() {
        let query_string: Vec<String> = params.iter().map(|(k, v)| format!("{k}={v}")).collect();
        target_msg_url.push('?');
        target_msg_url.push_str(&query_string.join("&"));
    }

    let mut req_builder = state.client.post(&target_msg_url).json(&payload);
    if let Some(ref token) = state.token {
        req_builder = req_builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }

    let resp = match req_builder.send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[agentguard-gateway] Error forwarding message to target: {e}");
            return Err((StatusCode::BAD_GATEWAY, "502 Bad Gateway"));
        }
    };

    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::OK);

    if let Ok(mut resp_json) = resp.json::<serde_json::Value>().await {
        // 3. Secret Redaction on response payload
        if let Some(ref redactor) = state.redactor {
            let count = redactor.redact_json(&mut resp_json);
            if count > 0 {
                eprintln!("[agentguard-redactor] REDACTED {count} secret(s) in HTTP POST response payload");
                state.audit_logger.log_event(
                    "secret_redaction",
                    "MEDIUM",
                    &format!("REDACTED {count} secret(s) in HTTP POST response payload"),
                );
            }
        }
        Ok((status, Json(resp_json)).into_response())
    } else {
        Ok(status.into_response())
    }
}

fn inspect_http_payload(
    jail: &PathJail,
    payload: &serde_json::Value,
    logger: &AuditLogger,
) -> Option<serde_json::Value> {
    let method = payload.get("method").and_then(|m| m.as_str());
    if method != Some("tools/call") {
        return None;
    }

    let tool_params = payload.get("params")?;

    if let Err(jail_err) = jail.inspect_json_arguments(tool_params) {
        let req_id = payload.get("id").cloned().unwrap_or(serde_json::Value::Null);
        eprintln!("[agentguard-jail] REJECTED tool call over HTTP: {jail_err}");
        logger.log_event(
            "path_jail_violation",
            "HIGH",
            &format!("REJECTED tool call over HTTP: {jail_err}"),
        );

        let err_resp = serde_json::json!({
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32602,
                "message": format!("SecurityViolation: {jail_err}")
            }
        });
        return Some(err_resp);
    }

    None
}
