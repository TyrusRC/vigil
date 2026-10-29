package openapiexpose

import "testing"

func TestIsSpecOrDocs_JSON(t *testing.T) {
	body := `{"openapi":"3.1.0","info":{"title":"My API"},"paths":{"/users":{"get":{}}}}`
	if !isSpecOrDocs(body) {
		t.Error("expected OpenAPI JSON spec to be detected")
	}
}

func TestIsSpecOrDocs_Swagger(t *testing.T) {
	body := `{"swagger":"2.0","info":{"title":"Legacy API"},"paths":{"/items":{"get":{}}}}`
	if !isSpecOrDocs(body) {
		t.Error("expected Swagger 2.0 spec to be detected")
	}
}

func TestIsSpecOrDocs_HTML(t *testing.T) {
	body := `<!DOCTYPE html><html><head><title>Swagger UI</title></head><body></body></html>`
	if !isSpecOrDocs(body) {
		t.Error("expected Swagger UI HTML to be detected")
	}
}

func TestIsSpecOrDocs_FastAPI(t *testing.T) {
	body := `<!DOCTYPE html><html><head><title>FastAPI - Swagger UI</title></head></html>`
	if !isSpecOrDocs(body) {
		t.Error("expected FastAPI docs to be detected")
	}
}

func TestIsSpecOrDocs_Redoc(t *testing.T) {
	body := `<!DOCTYPE html><html><head><title>ReDoc</title></head><body><redoc></redoc></body></html>`
	if !isSpecOrDocs(body) {
		t.Error("expected ReDoc page to be detected")
	}
}

func TestIsSpecOrDocs_NotDocs(t *testing.T) {
	body := `<!DOCTYPE html><html><body><h1>Welcome to our site</h1></body></html>`
	if isSpecOrDocs(body) {
		t.Error("expected generic HTML NOT to be detected as docs")
	}
}

func TestIsSpecOrDocs_ShortBody(t *testing.T) {
	body := `{}`
	if isSpecOrDocs(body) {
		t.Error("expected empty JSON NOT to be detected")
	}
}
