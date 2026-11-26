package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"
)

// fakeCLI puts a shell script called name on PATH for the duration of the test.
func fakeCLI(t *testing.T, name, script string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake CLIs are shell scripts")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func testServer() http.Handler {
	s := &server{
		controllerNamespace: "cd-sealed-secrets",
		controllerName:      "sealed-secrets",
		config:              []byte(`{"clusters":[]}`),
		static:              http.FileServerFS(fstest.MapFS{"index.html": {Data: []byte("hallo")}}),
		newClient:           newLoginClient,
	}
	return s.routes()
}

func get(t *testing.T, h http.Handler, host, path string) (*http.Response, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = host
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body, _ := io.ReadAll(rec.Result().Body)
	return rec.Result(), string(body)
}

func TestRejectsForeignHost(t *testing.T) {
	// A page on another site that rebinds its DNS to 127.0.0.1 still sends its own Host.
	res, _ := get(t, testServer(), "evil.example:8080", "/live-namespaces/current")
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", res.StatusCode)
	}
}

func TestServesConfigAndStaticFiles(t *testing.T) {
	h := testServer()
	res, body := get(t, h, "localhost:8080", "/config/clusters.json")
	if res.StatusCode != 200 || body != `{"clusters":[]}` || res.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("config: %d %q %q", res.StatusCode, body, res.Header.Get("Cache-Control"))
	}
	res, body = get(t, h, "127.0.0.1:8080", "/")
	if res.StatusCode != 200 || body != "hallo" {
		t.Fatalf("index: %d %q", res.StatusCode, body)
	}
	if !strings.Contains(res.Header.Get("Content-Security-Policy"), "connect-src 'self'") {
		t.Fatal("CSP ontbreekt")
	}
}

func TestRejectsContextThatLooksLikeAFlag(t *testing.T) {
	res, _ := get(t, testServer(), "localhost", "/live-certs/--kubeconfig=x")
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", res.StatusCode)
	}
}

func TestCertificateUsesContextAndReportsServer(t *testing.T) {
	fakeCLI(t, "kubeseal", `echo "-----BEGIN CERTIFICATE----- $* -----END CERTIFICATE-----"`)
	fakeCLI(t, "oc", `echo https://api.ont.example:6443`)

	res, body := get(t, testServer(), "localhost", "/live-certs/team%2Font")

	if res.StatusCode != 200 {
		t.Fatalf("status = %d: %s", res.StatusCode, body)
	}
	if !strings.Contains(body, "--context=team/ont") || !strings.Contains(body, "--controller-name=sealed-secrets") {
		t.Fatalf("kubeseal args: %s", body)
	}
	if got := res.Header.Get("X-Cluster-Server"); got != "https://api.ont.example:6443" {
		t.Fatalf("X-Cluster-Server = %q", got)
	}
}

func TestNamespacesSortedAsJSON(t *testing.T) {
	fakeCLI(t, "oc", `echo "team-b team-a"`)

	_, body := get(t, testServer(), "localhost", "/live-namespaces/current")

	if strings.TrimSpace(body) != `["team-a","team-b"]` {
		t.Fatalf("body = %s", body)
	}
}

func TestMissingCLIGivesReadableError(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	res, body := get(t, testServer(), "localhost", "/live-certs/current")

	if res.StatusCode != http.StatusBadGateway || !strings.Contains(body, "kubeseal is niet gevonden") {
		t.Fatalf("%d %q", res.StatusCode, body)
	}
}

func TestOcErrorWinsOverMissingKubectl(t *testing.T) {
	fakeCLI(t, "oc", `echo "error: You must be logged in to the server (Unauthorized)" >&2; exit 1`)
	t.Setenv("PATH", filepath.SplitList(os.Getenv("PATH"))[0]) // oc only, no kubectl

	_, body := get(t, testServer(), "localhost", "/live-namespaces/current")

	if !strings.Contains(body, "Unauthorized") {
		t.Fatalf("body = %q", body)
	}
}

func TestListenFallsBackWhenDefaultPortIsTaken(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	addr := taken.Addr().String()

	if l, err := listen(addr, true); err == nil {
		l.Close()
		t.Fatal("een zelf opgegeven bezette poort moet een fout geven")
	}
	l, err := listen(addr, false)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if l.Addr().String() == addr {
		t.Fatalf("verwachtte een andere poort dan %s", addr)
	}
}

// kubeseal puts the cause first and a generic --controller-name hint after it; show the cause.
func TestKubesealServiceErrorShowsCause(t *testing.T) {
	hint := `Please, use the flag --controller-name and --controller-namespace to set up the name and namespace of the sealed secrets controller`
	for cause, want := range map[string]string{
		`Unauthorized`:                        "oc-login is verlopen",
		`services "sealed-secrets" not found`: "Geen Sealed Secrets-controller gevonden op cd-sealed-secrets/sealed-secrets",
		`services "sealed-secrets" is forbidden: User "jos" cannot get resource "services"`: `User "jos" cannot get resource "services"`,
	} {
		fakeCLI(t, "kubeseal", `printf 'error: cannot get sealed secret service: %s.\n%s\n' '`+cause+`' '`+hint+`' >&2; exit 1`)
		res, body := get(t, testServer(), "localhost", "/live-certs/current")
		if res.StatusCode != http.StatusBadGateway || !strings.Contains(body, want) || strings.Contains(body, "Please") {
			t.Errorf("%s: %d %s", cause, res.StatusCode, body)
		}
	}
}
