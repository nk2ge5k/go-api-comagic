package comagic

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SessionLifetime is a duration after session key will be invalid
const SessionLifetime = time.Hour * 3

var DefaultBaseURL = &url.URL{Scheme: "http", Host: "api.comagic.ru"}

// WithTransport is an option function for setting custom http transport
func WithTransport(rt http.RoundTripper) func(*Transport) {
	return func(t *Transport) { t.Transport = rt }
}

// WithBaseURL is an option function for setting custom API base URL
func WithBaseURL(u *url.URL) func(*Transport) {
	return func(t *Transport) { t.BaseURL = u }
}

// New returns comagic API client
func New(login, password string, opts ...func(*Transport)) *http.Client {
	t := &Transport{}
	for _, opt := range opts {
		opt(t)
	}
	t.Login = login
	t.Password = password

	return &http.Client{Transport: t}
}

// Transport is http transport allowing to make requests comagic API a little bit easer
type Transport struct {
	// User credentials
	Login    string
	Password string

	// BaseULR for API requests
	BaseURL *url.URL

	// Underlying transport
	Transport http.RoundTripper

	session struct {
		key   string
		start time.Time
	}
}

// RoundTrip implements http.RoundrTripper interface allowing to
// send authorization request to comagic API before any actual.
// First request to API is not totaly concurent safe because it makes
// underlying authorization request and populates sessionKey
func (t *Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r == nil {
		return nil, fmt.Errorf("round trip: empty request")
	}
	if !t.sessionValid() {
		if err := t.auth(); err != nil {
			return nil, fmt.Errorf("round trip: could not authorize: %v", err)
		}
	}
	r.Header.Set("Accept", "application/json")
	if !r.URL.IsAbs() {
		r.URL = t.baseURL().ResolveReference(r.URL)
	}
	// add required session key
	v := r.URL.Query()
	v.Set("session_key", t.session.key)
	r.URL.RawQuery = v.Encode()
	// add required trailing slash
	if !strings.HasSuffix(r.URL.Path, "/") {
		r.URL.Path += "/"
	}
	return t.transport().RoundTrip(r)
}

func (t *Transport) sessionValid() bool {
	return len(t.session.key) > 0 && time.Since(t.session.start) < SessionLifetime
}

func (t *Transport) auth() error {
	reqURL := t.baseURL().ResolveReference(&url.URL{Path: "/api/login/"})
	buf := bytes.NewBuffer(nil)

	w := multipart.NewWriter(buf)
	w.WriteField("login", t.Login)
	w.WriteField("password", t.Password)
	w.Close()

	req, err := http.NewRequest(http.MethodPost, reqURL.String(), buf)
	if err != nil {
		return fmt.Errorf("auth: could not create request: %v", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", w.FormDataContentType())

	res, err := t.transport().RoundTrip(req)
	if err != nil {
		return fmt.Errorf("auth: request failed: %v", err)
	}

	defer res.Body.Close()
	if res.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("auth: invalid response: %d %s", res.StatusCode, http.StatusText(res.StatusCode))
	}
	ar := authResp{}
	if err := json.NewDecoder(res.Body).Decode(&ar); err != nil {
		return fmt.Errorf("auth: could not decode response: %v", err)
	}
	if !ar.Success {
		return fmt.Errorf("auth: request failed: %s", ar.Message)
	}
	t.session.key = ar.Data.SessionKey
	t.session.start = time.Now().Add(-time.Minute)
	return nil
}

func (t *Transport) baseURL() *url.URL {
	if t.BaseURL == nil {
		return DefaultBaseURL
	}
	return t.BaseURL
}

func (t *Transport) transport() http.RoundTripper {
	if t.Transport == nil {
		return http.DefaultTransport
	}
	return t.Transport
}

type authResp struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    struct {
		SessionKey string `json:"session_key"`
	} `json:"data"`
}
