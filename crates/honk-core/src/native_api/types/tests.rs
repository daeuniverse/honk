use super::*;

#[tokio::test]
async fn refusal_reasons_survive_all_details_types_and_builder_orders() {
    for details in [
        json!({"stage":"write"}),
        json!([1, "two"]),
        json!("text"),
        json!(42),
        json!(true),
        Value::Null,
    ] {
        let expected = match &details {
            Value::Object(fields) => {
                let mut fields = fields.clone();
                fields.insert("reason".into(), json!("unsafe_path"));
                Value::Object(fields)
            }
            value => json!({"value":value,"reason":"unsafe_path"}),
        };
        for reason_first in [false, true] {
            let error = ApiError::new(
                StatusCode::FORBIDDEN,
                ErrorCode::PermissionDenied,
                "Refused",
                None,
            );
            let error = if reason_first {
                error
                    .with_reason(WriteRefusal::UnsafePath)
                    .with_details(details.clone())
            } else {
                error
                    .with_details(details.clone())
                    .with_reason(WriteRefusal::UnsafePath)
            };
            let response = error.into_response();
            assert_eq!(
                response.extensions().get::<WriteRefusal>(),
                Some(&WriteRefusal::UnsafePath)
            );
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let body: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["error"]["details"], expected);
        }
    }
}
