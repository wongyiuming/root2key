mod bootstrap;

use std::{
    env,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use axum::{
    extract::{DefaultBodyLimit, Request, State},
    http::{
        header::{CACHE_CONTROL, EXPIRES, PRAGMA},
        HeaderName, HeaderValue, StatusCode,
    },
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use tokio::{net::TcpListener, task};

use bootstrap::{BootstrapFailure, BootstrapRequest};

#[derive(Default)]
struct AppState {
    busy: Arc<AtomicBool>,
}

struct BusyGuard(Arc<AtomicBool>);
impl Drop for BusyGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[derive(Serialize)]
struct ApiError {
    error: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    steps: Vec<String>,
}

#[tokio::main]
async fn main() {
    let addr = env::var("ROOT2KEY_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".to_owned());
    let state = Arc::new(AppState::default());
    let app = Router::new()
        .route("/", get(index))
        .route("/healthz", get(healthz))
        .route("/api/bootstrap", post(bootstrap_handler))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(middleware::from_fn(security_headers))
        .with_state(state);

    let listener = TcpListener::bind(&addr).await.expect("bind root2key listener");
    eprintln!("root2key listening on {addr}");
    axum::serve(listener, app).await.expect("serve root2key");
}

async fn index() -> Html<&'static str> {
    Html(include_str!("index.html"))
}

async fn healthz() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn bootstrap_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BootstrapRequest>,
) -> Response {
    if state
        .busy
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return (
            StatusCode::CONFLICT,
            Json(ApiError {
                error: "another bootstrap operation is already running".into(),
                steps: vec![],
            }),
        )
            .into_response();
    }

    let busy = state.busy.clone();
    let outcome = task::spawn_blocking(move || {
        let _guard = BusyGuard(busy);
        bootstrap::run(req)
    })
    .await;

    match outcome {
        Ok(Ok(result)) => (StatusCode::OK, Json(result)).into_response(),
        Ok(Err(BootstrapFailure { message, steps })) => (
            StatusCode::BAD_GATEWAY,
            Json(ApiError {
                error: message,
                steps,
            }),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError {
                error: format!("bootstrap worker failed: {err}"),
                steps: vec![],
            }),
        )
            .into_response(),
    }
}

async fn security_headers(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(EXPIRES, HeaderValue::from_static("0"));
    headers.insert(HeaderName::from_static("x-content-type-options"), HeaderValue::from_static("nosniff"));
    headers.insert(HeaderName::from_static("x-frame-options"), HeaderValue::from_static("DENY"));
    headers.insert(HeaderName::from_static("referrer-policy"), HeaderValue::from_static("no-referrer"));
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static("default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"),
    );
    response
}
