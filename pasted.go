package main

// A pasted `oc login --token=… --server=…` command. With it we talk to the Kubernetes API
// ourselves, so neither oc nor kubeseal has to be installed.
//
//	GET    /pasted-login             → {"connected", "server", "user"} of the current login
//	POST   /pasted-login             ← {"command": "oc login …"}; checks the token, then stores it
//	DELETE /pasted-login             → forget the login
//	GET    /pasted-login/cert        → sealing cert, like `kubeseal --fetch-cert`
//	GET    /pasted-login/namespaces  → JSON list of projects/namespaces you can see
//
// The token lives in memory only: never on disk, never in the browser's storage.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

type pastedLogin struct {
	server string
	token  string
	user   string
	client *http.Client
}

type loginStore struct {
	mu    sync.Mutex
	login *pastedLogin
}

func (s *loginStore) get() *pastedLogin {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.login
}

func (s *loginStore) set(l *pastedLogin) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.login = l
}

// clear forgets l, unless a newer login has replaced it in the meantime.
func (s *loginStore) clear(l *pastedLogin) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l == nil || s.login == l {
		s.login = nil
	}
}

type loginCommand struct {
	server   string
	token    string
	insecure bool
}

// parseLoginCommand understands what "Copy login command" in the OpenShift console gives you,
// plus the usual variations: `--flag value`, a server without --server, quotes.
func parseLoginCommand(command string) (loginCommand, error) {
	var c loginCommand
	fields := strings.Fields(strings.ReplaceAll(command, "\\\n", " "))
	for i := 0; i < len(fields); i++ {
		f := strings.Trim(fields[i], `"'`)
		name, value, hasValue := strings.Cut(f, "=")
		next := func() string {
			if hasValue {
				return strings.Trim(value, `"'`)
			}
			if i+1 < len(fields) {
				i++
				return strings.Trim(fields[i], `"'`)
			}
			return ""
		}
		switch name {
		case "--token":
			c.token = next()
		case "--server", "-s":
			c.server = next()
		case "--insecure-skip-tls-verify":
			c.insecure = !hasValue || value == "true"
		default:
			if strings.HasPrefix(f, "https://") {
				c.server = f
			}
		}
	}

	if c.token == "" {
		return c, errors.New("Geen token gevonden. Verwacht iets als: oc login --token=sha256~… --server=https://api…:6443")
	}
	if c.server == "" {
		return c, errors.New("Geen server gevonden. Verwacht iets als: oc login --token=sha256~… --server=https://api…:6443")
	}
	u, err := url.Parse(c.server)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return c, fmt.Errorf("Ongeldige server %q: verwacht https://…", c.server)
	}
	c.server = strings.TrimSuffix(u.Scheme+"://"+u.Host+u.Path, "/")
	return c, nil
}

func newLoginClient(insecure bool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		// Only when the pasted command asks for it, exactly like oc does.
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{Transport: transport, Timeout: 20 * time.Second}
}

// apiError is an error with the HTTP status it should be reported with.
type apiError struct {
	status  int
	message string
}

func (e *apiError) Error() string { return e.message }

var errTokenRejected = &apiError{http.StatusUnauthorized,
	"Het cluster accepteert de token niet (verlopen of ongeldig). Plak een nieuw oc login-commando."}

// apiGet does an authenticated GET against the cluster. 404 is returned as (nil, nil).
func (l *pastedLogin) apiGet(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.server+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+l.token)
	req.Header.Set("Accept", "application/json, */*")
	res, err := l.client.Do(req)
	if err != nil {
		var certErr *tls.CertificateVerificationError
		if errors.As(err, &certErr) {
			return nil, &apiError{http.StatusBadGateway, "Het certificaat van " + l.server +
				" wordt niet vertrouwd. Voeg --insecure-skip-tls-verify toe aan het commando als je zeker weet dat het adres klopt."}
		}
		return nil, &apiError{http.StatusBadGateway, "Kan " + l.server + " niet bereiken: " + rootCause(err)}
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	switch {
	case res.StatusCode == http.StatusUnauthorized:
		return nil, errTokenRejected
	case res.StatusCode == http.StatusNotFound:
		return nil, nil
	case res.StatusCode == http.StatusForbidden:
		return nil, &apiError{http.StatusForbidden, "Geen rechten voor " + path + ": " + statusMessage(body)}
	case res.StatusCode >= 300:
		return nil, &apiError{http.StatusBadGateway, fmt.Sprintf("Cluster gaf %d op %s: %s", res.StatusCode, path, statusMessage(body))}
	}
	return body, nil
}

// whoami checks the token. On clusters without the OpenShift user API there is no name to show.
func (l *pastedLogin) whoami(ctx context.Context) (string, error) {
	body, err := l.apiGet(ctx, "/apis/user.openshift.io/v1/users/~")
	if err != nil || body == nil {
		return "", err
	}
	var user struct {
		Metadata struct{ Name string } `json:"metadata"`
	}
	json.Unmarshal(body, &user)
	return user.Metadata.Name, nil
}

func (s *server) handleLoginStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	l := s.logins.get()
	if l == nil {
		writeJSON(w, map[string]any{"connected": false})
		return
	}
	writeJSON(w, map[string]any{"connected": true, "server": l.server, "user": l.user})
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var body struct{ Command string }
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&body); err != nil {
		http.Error(w, "Ongeldig verzoek", http.StatusBadRequest)
		return
	}
	cmd, err := parseLoginCommand(body.Command)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	l := &pastedLogin{server: cmd.server, token: cmd.token, client: s.newClient(cmd.insecure)}
	if l.user, err = l.whoami(r.Context()); err != nil {
		writeAPIError(w, err)
		return
	}
	s.logins.set(l)
	writeJSON(w, map[string]any{"connected": true, "server": l.server, "user": l.user})
}

func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.logins.clear(nil)
	w.WriteHeader(http.StatusNoContent)
}

// withLogin runs handler with the current login, and forgets that login once the cluster rejects it.
func (s *server) withLogin(handler func(context.Context, *pastedLogin, http.ResponseWriter) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		l := s.logins.get()
		if l == nil {
			http.Error(w, "Nog niet verbonden. Plak je oc login-commando.", http.StatusUnauthorized)
			return
		}
		if err := handler(r.Context(), l, w); err != nil {
			if errors.Is(err, errTokenRejected) {
				s.logins.clear(l)
			}
			writeAPIError(w, err)
		}
	}
}

// pastedCertificate fetches the cert the way kubeseal does: through the controller's service proxy.
func (s *server) pastedCertificate(ctx context.Context, l *pastedLogin, w http.ResponseWriter) error {
	path := fmt.Sprintf("/api/v1/namespaces/%s/services/http:%s:/proxy/v1/cert.pem",
		url.PathEscape(s.controllerNamespace), url.PathEscape(s.controllerName))
	body, err := l.apiGet(ctx, path)
	if err != nil {
		return err
	}
	if body == nil {
		return &apiError{http.StatusBadGateway, fmt.Sprintf(
			"Geen Sealed Secrets-controller gevonden op %s/%s. Klopt SEALED_SECRETS_NAMESPACE/SEALED_SECRETS_NAME?",
			s.controllerNamespace, s.controllerName)}
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("X-Cluster-Server", l.server)
	_, err = w.Write(body)
	return err
}

// pastedNamespaces lists OpenShift projects (only what you can access), or plain namespaces elsewhere.
func (s *server) pastedNamespaces(ctx context.Context, l *pastedLogin, w http.ResponseWriter) error {
	body, err := l.apiGet(ctx, "/apis/project.openshift.io/v1/projects")
	if err == nil && body == nil {
		body, err = l.apiGet(ctx, "/api/v1/namespaces")
	}
	if err != nil {
		return err
	}
	var list struct {
		Items []struct {
			Metadata struct{ Name string } `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return &apiError{http.StatusBadGateway, "Onverwacht antwoord van het cluster bij het ophalen van namespaces"}
	}
	names := make([]string, 0, len(list.Items))
	for _, item := range list.Items {
		names = append(names, item.Metadata.Name)
	}
	sort.Strings(names)
	writeJSON(w, names)
	return nil
}

func writeAPIError(w http.ResponseWriter, err error) {
	var apiErr *apiError
	if errors.As(err, &apiErr) {
		http.Error(w, apiErr.message, apiErr.status)
		return
	}
	http.Error(w, err.Error(), http.StatusBadGateway)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// statusMessage pulls the message out of a Kubernetes Status object, if that's what we got.
func statusMessage(body []byte) string {
	var status struct{ Message string }
	if json.Unmarshal(body, &status) == nil && status.Message != "" {
		return status.Message
	}
	text := strings.TrimSpace(string(body))
	if len(text) > 200 || strings.Contains(text, "<") {
		return "(geen leesbare foutmelding)"
	}
	return text
}

func rootCause(err error) string {
	for {
		next := errors.Unwrap(err)
		if next == nil {
			return err.Error()
		}
		err = next
	}
}
