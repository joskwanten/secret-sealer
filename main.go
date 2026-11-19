// Command secret-sealer serves the Secret Sealer web app on your own machine.
//
// The page in web/ is baked into the binary. On top of that it answers two live lookups
// with your own oc/kubectl login, so you don't have to maintain cert files or namespace
// lists for local use:
//
//	GET /live-certs/current               → sealing cert of the cluster you're logged in to
//	GET /live-namespaces/current          → JSON list of projects/namespaces you can see
//	GET /live-<…>/<url-encoded context>   → same, via a specific kubeconfig context
//
// Sealing itself still happens in the browser; your secret never reaches this program.
package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"
)

//go:embed web
var webFiles embed.FS

//go:embed local-config/clusters.json
var localConfig []byte

const csp = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; connect-src 'self'; form-action 'none'; base-uri 'self'; frame-ancestors 'none'"

type server struct {
	controllerNamespace string
	controllerName      string
	config              []byte
	static              http.Handler
	logins              loginStore
	newClient           func(insecure bool) *http.Client
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "adres om op te luisteren (blijf op localhost)")
	configPath := flag.String("config", "", "eigen clusters.json in plaats van de ingebouwde")
	dev := flag.Bool("dev", false, "serveer ./web van schijf (voor ontwikkelen, geen herstart nodig)")
	open := flag.Bool("open", true, "open de browser bij het starten")
	flag.Parse()

	var files fs.FS
	if *dev {
		files = os.DirFS("web")
	} else {
		sub, err := fs.Sub(webFiles, "web")
		if err != nil {
			log.Fatal(err)
		}
		files = sub
	}

	config := localConfig
	if *configPath != "" {
		var err error
		if config, err = os.ReadFile(*configPath); err != nil {
			log.Fatalf("config lezen: %v", err)
		}
	}

	s := &server{
		controllerNamespace: envOr("SEALED_SECRETS_NAMESPACE", "cd-sealed-secrets"),
		controllerName:      envOr("SEALED_SECRETS_NAME", "sealed-secrets"),
		config:              config,
		static:              http.FileServerFS(files),
		newClient:           newLoginClient,
	}

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	url := "http://" + displayAddr(listener.Addr().String()) + "/"
	log.Printf("Secret Sealer draait op %s (Ctrl+C om te stoppen)", url)
	if *open {
		openBrowser(url)
	}
	log.Fatal(http.Serve(listener, s.routes()))
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /config/clusters.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(s.config)
	})
	mux.HandleFunc("GET /live-certs/{context}", s.live(s.certificate))
	mux.HandleFunc("GET /live-namespaces/{context}", s.live(s.namespaces))
	mux.HandleFunc("GET /pasted-login", s.handleLoginStatus)
	mux.HandleFunc("POST /pasted-login", sameOrigin(s.handleLogin))
	mux.HandleFunc("DELETE /pasted-login", sameOrigin(s.handleLogout))
	mux.HandleFunc("GET /pasted-login/cert", s.withLogin(s.pastedCertificate))
	mux.HandleFunc("GET /pasted-login/namespaces", s.withLogin(s.pastedNamespaces))
	mux.Handle("GET /", s.static)
	return localOnly(securityHeaders(mux))
}

// live wraps a lookup with the error handling of the old dev-server proxy.
func (s *server) live(handler func(ctx context.Context, kubeContext string, w http.ResponseWriter) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		kubeContext := r.PathValue("context")
		if kubeContext == "" || strings.HasPrefix(kubeContext, "-") {
			http.Error(w, "Ongeldige context", http.StatusBadRequest)
			return
		}
		if err := handler(r.Context(), kubeContext, w); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
		}
	}
}

func (s *server) certificate(ctx context.Context, kubeContext string, w http.ResponseWriter) error {
	server := make(chan string, 1)
	go func() { server <- s.apiServer(ctx, kubeContext) }()

	pem, err := run(ctx, 20*time.Second, "kubeseal", append([]string{
		"--controller-namespace=" + s.controllerNamespace,
		"--controller-name=" + s.controllerName,
	}, append(contextArgs(kubeContext), "--fetch-cert")...)...)
	if err != nil {
		return err
	}
	if addr := <-server; addr != "" {
		w.Header().Set("X-Cluster-Server", addr)
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, err = io.WriteString(w, pem)
	return err
}

// apiServer is best effort: which API server we talked to, so you can see you have the right cluster.
func (s *server) apiServer(ctx context.Context, kubeContext string) string {
	attempts := [][]string{
		append([]string{"oc", "whoami", "--show-server"}, contextArgs(kubeContext)...),
		append([]string{"kubectl", "config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}"}, contextArgs(kubeContext)...),
	}
	for _, cmd := range attempts {
		if out, err := run(ctx, 5*time.Second, cmd[0], cmd[1:]...); err == nil && strings.TrimSpace(out) != "" {
			return strings.TrimSpace(out)
		}
	}
	return ""
}

// namespaces lists OpenShift projects first: those only include what you have access to, so
// they work without cluster-wide rights. Plain namespaces are the fallback for other clusters.
func (s *server) namespaces(ctx context.Context, kubeContext string, w http.ResponseWriter) error {
	jsonpath := []string{"-o", "jsonpath={.items[*].metadata.name}"}
	var errs []error
	for _, cmd := range [][]string{
		append(append([]string{"oc", "get", "projects"}, jsonpath...), contextArgs(kubeContext)...),
		append(append([]string{"kubectl", "get", "namespaces"}, jsonpath...), contextArgs(kubeContext)...),
	} {
		out, err := run(ctx, 20*time.Second, cmd[0], cmd[1:]...)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		names := strings.Fields(out)
		sort.Strings(names)
		if names == nil {
			names = []string{}
		}
		w.Header().Set("Content-Type", "application/json")
		return json.NewEncoder(w).Encode(names)
	}
	// A real error from oc (e.g. Unauthorized) says more than "kubectl not installed".
	for _, err := range errs {
		if !errors.As(err, new(notFoundError)) {
			return err
		}
	}
	return errs[0]
}

type notFoundError struct{ name string }

func (e notFoundError) Error() string {
	return e.name + " is niet gevonden. Staat het in je PATH?"
}

// run executes a CLI and turns failures into a short, readable Dutch message.
func run(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	hideWindow(cmd)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err == nil {
		return string(out), nil
	}
	if errors.Is(err, exec.ErrNotFound) {
		return "", notFoundError{name}
	}
	detail := lastLine(stderr.String())
	if detail == "" {
		detail = err.Error()
	}
	return "", fmt.Errorf("Fout bij %s: %s. Ben je ingelogd met oc login?", name, strings.TrimSuffix(detail, "."))
}

func contextArgs(kubeContext string) []string {
	if kubeContext == "current" {
		return nil
	}
	return []string{"--context=" + kubeContext}
}

// localOnly refuses requests whose Host isn't localhost. The live endpoints run kubeseal and oc
// with your login, so a web page must not reach them through DNS rebinding.
func localOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		switch host {
		case "localhost", "127.0.0.1", "::1":
			next.ServeHTTP(w, r)
		default:
			http.Error(w, "Alleen bereikbaar via localhost", http.StatusForbidden)
		}
	})
}

// sameOrigin only lets our own page change the login. Without it, any website you visit could
// post its own token and server, and you'd seal your secrets with a key of theirs.
func sameOrigin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Sec-Fetch-Site") != "same-origin" && r.Header.Get("Origin") != "http://"+r.Host {
			http.Error(w, "Alleen vanaf de Secret Sealer-pagina zelf", http.StatusForbidden)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") && r.Method == http.MethodPost {
			http.Error(w, "Verwacht JSON", http.StatusUnsupportedMediaType)
			return
		}
		next(w, r)
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-cache")
		next.ServeHTTP(w, r)
	})
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func displayAddr(addr string) string {
	return strings.Replace(addr, "127.0.0.1", "localhost", 1)
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		log.Printf("Open zelf %s in je browser", url)
	}
}
