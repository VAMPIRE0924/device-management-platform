package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerServesIndexAndSPAFallback(t *testing.T) {
	handler := Handler()
	for _, requestPath := range []string{"/", "/projects/example"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, requestPath, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s: status = %d", requestPath, recorder.Code)
		}
		if !strings.Contains(recorder.Body.String(), "远程管理平台") {
			t.Fatalf("%s: expected branded index", requestPath)
		}
	}
}

func TestHandlerDoesNotMaskReservedOrMissingAssetRoutes(t *testing.T) {
	handler := Handler()
	for _, requestPath := range []string{"/api/v1/missing", "/access/missing", "/health/missing", "/assets/missing.js"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, requestPath, nil))
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("%s: status = %d, want 404", requestPath, recorder.Code)
		}
	}
}
