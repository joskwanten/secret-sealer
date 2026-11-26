package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestParseLoginCommand(t *testing.T) {
	for _, tc := range []struct {
		in       string
		server   string
		token    string
		insecure bool
	}{
		{"oc login --token=sha256~abc --server=https://api.ont.example:6443", "https://api.ont.example:6443", "sha256~abc", false},
		{"oc login --token sha256~abc --server https://api.ont.example:6443/", "https://api.ont.example:6443", "sha256~abc", false},
		{"oc login https://api.ont.example:6443 --token=sha256~abc --insecure-skip-tls-verify", "https://api.ont.example:6443", "sha256~abc", true},
		{"oc login --token='sha256~abc' \\\n  --server=\"https://api.ont.example:6443\" --insecure-skip-tls-verify=false", "https://api.ont.example:6443", "sha256~abc", false},
	} {
		got, err := parseLoginCommand(tc.in)
		if err != nil || got.server != tc.server || got.token != tc.token || got.insecure != tc.insecure {
			t.Errorf("%q → %+v, %v", tc.in, got, err)
		}
	}
	for _, bad := range []string{"", "oc login --server=https://api:6443", "oc login --token=x", "oc login --token=x --server=http://api:6443"} {
		if _, err := parseLoginCommand(bad); err == nil {
			t.Errorf("%q: verwachtte een fout", bad)
		}
	}
}

// fakeAPI is an OpenShift API server that accepts one token.
func fakeAPI(t *testing.T, token *atomic.Value) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /apis/user.openshift.io/v1/users/~", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"metadata":{"name":"jos"}}`)
	})
	// Like the Helm chart: a named port, which the proxy path has to mention.
	mux.HandleFunc("GET /api/v1/namespaces/cd-sealed-secrets/services/sealed-secrets", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"spec":{"ports":[{"name":"http","port":8080}]}}`)
	})
	mux.HandleFunc("GET /api/v1/namespaces/cd-sealed-secrets/services/http:sealed-secrets:http/proxy/v1/cert.pem",
		func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "-----BEGIN CERTIFICATE-----") })
	mux.HandleFunc("GET /apis/project.openshift.io/v1/projects", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"items":[{"metadata":{"name":"team-b"}},{"metadata":{"name":"team-a"}}]}`)
	})
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token.Load().(string) {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"kind":"Status","message":"Unauthorized"}`)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(api.Close)
	return api
}

func call(t *testing.T, h http.Handler, method, path, body string, sameOrigin bool) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = "localhost:8080"
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if sameOrigin {
		req.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, strings.TrimSpace(rec.Body.String())
}

func loginBody(command string) string {
	b, _ := json.Marshal(map[string]string{"command": command})
	return string(b)
}

func TestPastedLoginFlow(t *testing.T) {
	var token atomic.Value
	token.Store("sha256~goed")
	api := fakeAPI(t, &token)
	h := testServer()
	command := "oc login --token=sha256~goed --server=" + api.URL + " --insecure-skip-tls-verify"

	if code, body := call(t, h, "GET", "/pasted-login/cert", "", false); code != 401 {
		t.Fatalf("cert zonder login: %d %s", code, body)
	}
	if code, _ := call(t, h, "POST", "/pasted-login", loginBody(command), false); code != 403 {
		t.Fatalf("POST van een andere site: %d, want 403", code)
	}
	if code, body := call(t, h, "POST", "/pasted-login", loginBody(command), true); code != 200 || !strings.Contains(body, `"user":"jos"`) {
		t.Fatalf("login: %d %s", code, body)
	}
	if _, body := call(t, h, "GET", "/pasted-login", "", false); !strings.Contains(body, `"connected":true`) || strings.Contains(body, "sha256") {
		t.Fatalf("status: %s", body)
	}
	if code, body := call(t, h, "GET", "/pasted-login/cert", "", false); code != 200 || body != "-----BEGIN CERTIFICATE-----" {
		t.Fatalf("cert: %d %s", code, body)
	}
	if _, body := call(t, h, "GET", "/pasted-login/namespaces", "", false); body != `["team-a","team-b"]` {
		t.Fatalf("namespaces: %s", body)
	}

	token.Store("sha256~nieuw") // the pasted token expired
	if code, body := call(t, h, "GET", "/pasted-login/cert", "", false); code != 401 || !strings.Contains(body, "verlopen") {
		t.Fatalf("verlopen token: %d %s", code, body)
	}
	if _, body := call(t, h, "GET", "/pasted-login", "", false); body != `{"connected":false}` {
		t.Fatalf("login niet vergeten na 401: %s", body)
	}
}

func TestPastedLoginRejectsBadToken(t *testing.T) {
	var token atomic.Value
	token.Store("sha256~goed")
	api := fakeAPI(t, &token)
	h := testServer()

	code, body := call(t, h, "POST", "/pasted-login",
		loginBody("oc login --token=sha256~fout --server="+api.URL+" --insecure-skip-tls-verify"), true)

	if code != 401 || !strings.Contains(body, "token niet") {
		t.Fatalf("%d %s", code, body)
	}
	if _, body := call(t, h, "GET", "/pasted-login", "", false); body != `{"connected":false}` {
		t.Fatalf("status: %s", body)
	}
}

func TestPastedLoginExplainsUntrustedCertificate(t *testing.T) {
	var token atomic.Value
	token.Store("sha256~goed")
	api := fakeAPI(t, &token)

	_, body := call(t, testServer(), "POST", "/pasted-login",
		loginBody("oc login --token=sha256~goed --server="+api.URL), true)

	if !strings.Contains(body, "niet vertrouwd") || !strings.Contains(body, "--insecure-skip-tls-verify") {
		t.Fatalf("body = %s", body)
	}
}

func TestLogout(t *testing.T) {
	var token atomic.Value
	token.Store("sha256~goed")
	api := fakeAPI(t, &token)
	h := testServer()
	call(t, h, "POST", "/pasted-login", loginBody("oc login --token=sha256~goed --server="+api.URL+" --insecure-skip-tls-verify"), true)

	if code, _ := call(t, h, "DELETE", "/pasted-login", "", true); code != 204 {
		t.Fatalf("logout: %d", code)
	}
	if _, body := call(t, h, "GET", "/pasted-login", "", false); body != `{"connected":false}` {
		t.Fatalf("status: %s", body)
	}
}
