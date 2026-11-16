from app.observability import _safe_request_attributes


def test_logfire_request_attributes_drop_query_values_and_error_inputs():
    attributes = _safe_request_attributes(
        None,
        {
            "values": {"q": "private account name"},
            "errors": [
                {
                    "loc": ["query", "q"],
                    "type": "string_type",
                    "input": "private account name",
                }
            ],
        },
    )

    assert attributes == {
        "values": {},
        "errors": [{"loc": ["query", "q"], "type": "string_type"}],
    }
