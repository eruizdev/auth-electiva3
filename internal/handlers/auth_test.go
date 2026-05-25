package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func setupRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	return r
}

func TestRegister_MissingFields(t *testing.T) {
	r := setupRouter()
	r.POST("/auth/register", Register)

	body := `{"email":"test@test.com"}` // falta password y name
	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	// Sin DB conectada esperamos error (400 o 500)
	if w.Code == http.StatusOK {
		t.Errorf("Esperaba error, got 200")
	}
}

func TestLogin_InvalidJSON(t *testing.T) {
	r := setupRouter()
	r.POST("/auth/login", Login)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader("not-json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Esperaba 400, got %d", w.Code)
	}
}

func TestRefresh_InvalidJSON(t *testing.T) {
	r := setupRouter()
	r.POST("/auth/refresh", Refresh)

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", strings.NewReader("bad"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Esperaba 400, got %d", w.Code)
	}
}

func TestLogout_EmptyBody(t *testing.T) {
	r := setupRouter()
	r.POST("/auth/logout", Logout)

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	// Logout sin token activo igual responde 200
	if w.Code != http.StatusOK {
		t.Errorf("Esperaba 200, got %d", w.Code)
	}
}
