//! The error body, with fixed codes and generic messages.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use strig::QueryError;

/// Stable error codes. A code never changes meaning; new ones are added, so match with a
/// wildcard arm. A code this version does not know (a newer server) reads as
/// [`ErrorCode::Unknown`] with the text it came in, so an old client still reads the body.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// 400: the body is not JSON.
    MalformedJson,
    /// 400: valid JSON that does not fit the route's schema, a `layout` that does not start with
    /// `kind`, or a bad deadline header.
    InvalidRequest,
    /// 400: more checks than `max_batch`.
    BatchTooLarge,
    /// 400: more candidate resources than `max_resources`.
    TooManyResources,
    /// 413: the body is over the limit.
    BodyTooLarge,
    /// 415: the body is not `application/json`.
    UnsupportedMediaType,
    /// 404: no such route.
    NotFound,
    /// 405: the route does not take this method.
    MethodNotAllowed,
    /// 503: the policy or the grants could not be loaded.
    SourceUnavailable,
    /// 503: the query went past a `QueryLimits` ceiling or the work budget of the server.
    QueryLimitExceeded,
    /// 503: a relation chain went deeper than the engine allows and a deny could not be read.
    RelationDepthExceeded,
    /// 503: the deadline passed before the answer was ready.
    DeadlineExceeded,
    /// 503: no work slot was free before the deadline.
    Overloaded,
    /// 503: the server clock has no usable instant.
    ClockUnavailable,
    /// 503: the data the server decides from is older than the `min_revision` the request requires,
    /// and did not catch up before the deadline.
    RevisionNotReached,
    /// 503: the required revision cannot be compared with the data: it belongs to another data
    /// scope, or the source does not number its writes.
    RevisionMismatch,
    /// 503: anything else that went wrong inside the server, a panic included.
    Internal,
    /// A code this version does not know. The server never sends it; it only comes out of
    /// reading a body. It counts as fail-closed.
    Unknown(String),
}

impl ErrorCode {
    /// The text of the code on the wire.
    pub fn as_str(&self) -> &str {
        match self {
            ErrorCode::MalformedJson => "malformed_json",
            ErrorCode::InvalidRequest => "invalid_request",
            ErrorCode::BatchTooLarge => "batch_too_large",
            ErrorCode::TooManyResources => "too_many_resources",
            ErrorCode::BodyTooLarge => "body_too_large",
            ErrorCode::UnsupportedMediaType => "unsupported_media_type",
            ErrorCode::NotFound => "not_found",
            ErrorCode::MethodNotAllowed => "method_not_allowed",
            ErrorCode::SourceUnavailable => "source_unavailable",
            ErrorCode::QueryLimitExceeded => "query_limit_exceeded",
            ErrorCode::RelationDepthExceeded => "relation_depth_exceeded",
            ErrorCode::DeadlineExceeded => "deadline_exceeded",
            ErrorCode::Overloaded => "overloaded",
            ErrorCode::ClockUnavailable => "clock_unavailable",
            ErrorCode::RevisionNotReached => "revision_not_reached",
            ErrorCode::RevisionMismatch => "revision_mismatch",
            ErrorCode::Internal => "internal",
            ErrorCode::Unknown(code) => code,
        }
    }

    pub fn status(&self) -> StatusCode {
        match self {
            ErrorCode::MalformedJson
            | ErrorCode::InvalidRequest
            | ErrorCode::BatchTooLarge
            | ErrorCode::TooManyResources => StatusCode::BAD_REQUEST,
            ErrorCode::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ErrorCode::NotFound => StatusCode::NOT_FOUND,
            ErrorCode::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            ErrorCode::SourceUnavailable
            | ErrorCode::QueryLimitExceeded
            | ErrorCode::RelationDepthExceeded
            | ErrorCode::DeadlineExceeded
            | ErrorCode::Overloaded
            | ErrorCode::ClockUnavailable
            | ErrorCode::RevisionNotReached
            | ErrorCode::RevisionMismatch
            | ErrorCode::Internal
            | ErrorCode::Unknown(_) => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    /// The message that goes with the code. It is fixed on purpose: names of tables, paths and
    /// driver messages stay in the server log.
    pub fn message(&self) -> &'static str {
        match self {
            ErrorCode::MalformedJson => "the request body is not valid JSON",
            ErrorCode::InvalidRequest => "the request does not match the schema of this route",
            ErrorCode::BatchTooLarge => "the batch has more checks than the server accepts",
            ErrorCode::TooManyResources => "the request names more resources than the server accepts",
            ErrorCode::BodyTooLarge => "the request body is larger than the server accepts",
            ErrorCode::UnsupportedMediaType => "the request body must be application/json",
            ErrorCode::NotFound => "no such route",
            ErrorCode::MethodNotAllowed => "method not allowed on this route",
            ErrorCode::SourceUnavailable => "the grant source is unavailable; access is denied",
            ErrorCode::QueryLimitExceeded => "the query is over the server limits; access is denied",
            ErrorCode::RelationDepthExceeded => "a relation chain is too deep to read; access is denied",
            ErrorCode::DeadlineExceeded => "the deadline passed before an answer was ready; access is denied",
            ErrorCode::Overloaded => "the server is at capacity; access is denied",
            ErrorCode::ClockUnavailable => "the server clock is unavailable; access is denied",
            ErrorCode::RevisionNotReached => "the server has not reached the required revision; access is denied",
            ErrorCode::RevisionMismatch => {
                "the required revision cannot be compared with the server data; access is denied"
            }
            ErrorCode::Internal => "internal error; access is denied",
            ErrorCode::Unknown(_) => "unrecognized error; access is denied",
        }
    }

    /// Whether the code is one of the fail-closed answers (status 503).
    pub fn is_fail_closed(&self) -> bool {
        self.status() == StatusCode::SERVICE_UNAVAILABLE
    }
}

impl From<&str> for ErrorCode {
    fn from(code: &str) -> Self {
        match code {
            "malformed_json" => ErrorCode::MalformedJson,
            "invalid_request" => ErrorCode::InvalidRequest,
            "batch_too_large" => ErrorCode::BatchTooLarge,
            "too_many_resources" => ErrorCode::TooManyResources,
            "body_too_large" => ErrorCode::BodyTooLarge,
            "unsupported_media_type" => ErrorCode::UnsupportedMediaType,
            "not_found" => ErrorCode::NotFound,
            "method_not_allowed" => ErrorCode::MethodNotAllowed,
            "source_unavailable" => ErrorCode::SourceUnavailable,
            "query_limit_exceeded" => ErrorCode::QueryLimitExceeded,
            "relation_depth_exceeded" => ErrorCode::RelationDepthExceeded,
            "deadline_exceeded" => ErrorCode::DeadlineExceeded,
            "overloaded" => ErrorCode::Overloaded,
            "clock_unavailable" => ErrorCode::ClockUnavailable,
            "revision_not_reached" => ErrorCode::RevisionNotReached,
            "revision_mismatch" => ErrorCode::RevisionMismatch,
            "internal" => ErrorCode::Internal,
            other => ErrorCode::Unknown(other.to_owned()),
        }
    }
}

impl Serialize for ErrorCode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ErrorCode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Ok(ErrorCode::from(text.as_str()))
    }
}

/// `{"error": {"code": "...", "message": "..."}}`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: ErrorDetail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorDetail {
    pub code: ErrorCode,
    pub message: String,
}

impl ErrorBody {
    pub fn new(code: ErrorCode) -> Self {
        let message = code.message().to_string();
        Self {
            error: ErrorDetail { code, message },
        }
    }
}

/// An error that becomes the stable body and its status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub code: ErrorCode,
}

impl ApiError {
    pub fn new(code: ErrorCode) -> Self {
        Self { code }
    }
}

impl From<QueryError> for ApiError {
    fn from(error: QueryError) -> Self {
        // The detail (the limit, the grant id) stays in the log.
        tracing::warn!(error = %error, "reverse query failed closed");
        match error {
            QueryError::LimitExceeded { .. } => ApiError::new(ErrorCode::QueryLimitExceeded),
            QueryError::RelationDepthExceeded { .. } => ApiError::new(ErrorCode::RelationDepthExceeded),
            // `UnknownSubject` cannot come out of the routes (they never load a subject by
            // reference); the enum is non-exhaustive, so anything else is an internal error.
            _ => ApiError::new(ErrorCode::Internal),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        #[cfg(feature = "tracing")]
        crate::obs::error(self.code.as_str());
        if self.code.is_fail_closed() {
            tracing::warn!(code = self.code.as_str(), "answering 503, access denied");
        }
        (self.code.status(), Json(ErrorBody::new(self.code))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every known code with the status and the text the contract (`API.md`) promises.
    const TABLE: [(ErrorCode, u16, &str); 17] = [
        (ErrorCode::MalformedJson, 400, "malformed_json"),
        (ErrorCode::InvalidRequest, 400, "invalid_request"),
        (ErrorCode::BatchTooLarge, 400, "batch_too_large"),
        (ErrorCode::TooManyResources, 400, "too_many_resources"),
        (ErrorCode::NotFound, 404, "not_found"),
        (ErrorCode::MethodNotAllowed, 405, "method_not_allowed"),
        (ErrorCode::BodyTooLarge, 413, "body_too_large"),
        (ErrorCode::UnsupportedMediaType, 415, "unsupported_media_type"),
        (ErrorCode::SourceUnavailable, 503, "source_unavailable"),
        (ErrorCode::QueryLimitExceeded, 503, "query_limit_exceeded"),
        (ErrorCode::RelationDepthExceeded, 503, "relation_depth_exceeded"),
        (ErrorCode::DeadlineExceeded, 503, "deadline_exceeded"),
        (ErrorCode::Overloaded, 503, "overloaded"),
        (ErrorCode::ClockUnavailable, 503, "clock_unavailable"),
        (ErrorCode::RevisionNotReached, 503, "revision_not_reached"),
        (ErrorCode::RevisionMismatch, 503, "revision_mismatch"),
        (ErrorCode::Internal, 503, "internal"),
    ];

    #[test]
    fn every_code_keeps_its_status_and_its_wire_text() {
        for (code, status, text) in TABLE {
            assert_eq!(code.status().as_u16(), status, "{text}");
            assert_eq!(code.as_str(), text);
            assert_eq!(serde_json::to_value(&code).unwrap(), text);
            assert_eq!(serde_json::from_value::<ErrorCode>(text.into()).unwrap(), code);
        }
    }

    #[test]
    fn an_unknown_code_is_read_not_refused() {
        let body: ErrorBody = serde_json::from_str(r#"{"error":{"code":"brand_new","message":"m"}}"#).unwrap();
        assert_eq!(body.error.code, ErrorCode::Unknown("brand_new".into()));
        assert!(body.error.code.is_fail_closed());
        assert_eq!(serde_json::to_value(&body.error.code).unwrap(), "brand_new");
    }
}
