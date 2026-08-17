package nodeadapter

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type ErrorKind string

const (
	ErrorAuthentication ErrorKind = "authentication"
	ErrorMethod         ErrorKind = "method"
	ErrorBusiness       ErrorKind = "business"
	ErrorHTTP           ErrorKind = "http"
)

type APIError struct {
	Kind       ErrorKind
	HTTPStatus int
	Message    string
}

func (e *APIError) Error() string {
	if e.HTTPStatus > 0 {
		return fmt.Sprintf("NPS %s error (HTTP %d): %s", e.Kind, e.HTTPStatus, e.Message)
	}
	return fmt.Sprintf("NPS %s error: %s", e.Kind, e.Message)
}

type responseEnvelope struct {
	Status *int `json:"status"`
	Code   *int `json:"code"`
}

func classifyNPSHTTPError(status int, payload []byte) error {
	kind := ErrorHTTP
	switch status {
	case http.StatusUnauthorized:
		kind = ErrorAuthentication
	case http.StatusMethodNotAllowed:
		kind = ErrorMethod
	}
	return &APIError{Kind: kind, HTTPStatus: status, Message: http.StatusText(status)}
}

func validateNPSBusinessResponse(payload []byte) error {
	var envelope responseEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return fmt.Errorf("decode node response: %w", err)
	}
	if (envelope.Status != nil && *envelope.Status == 0) || (envelope.Code != nil && *envelope.Code == 0) {
		return &APIError{Kind: ErrorBusiness, Message: "business operation rejected"}
	}
	return nil
}
