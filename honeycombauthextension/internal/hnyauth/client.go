// Copyright Honeycomb
// SPDX-License-Identifier: Apache-2.0

// Package hnyauth calls Honeycomb's /1/auth endpoint to validate an ingest key
// and resolve its team/environment. The request/response shape follows
// Refinery's AuthInfo lookup (refinery/route/route.go).
package hnyauth // import "github.com/honeycombio/honeycomb-auth-extension/honeycombauthextension/internal/hnyauth"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ErrInvalidKey means /1/auth returned 401: the key is invalid or revoked.
// It is distinct from transient/transport errors so that only invalid keys are
// negatively cached, and only transient failures fall back to stale results.
var ErrInvalidKey = errors.New("honeycomb api key is invalid")

// authKeyHeader is the header /1/auth expects the key on. This is fixed
// regardless of which inbound header the client used to send the key.
const authKeyHeader = "x-honeycomb-team"

const userAgent = "honeycomb-auth-extension"

const (
	// maxResponseBytes caps how much of a /1/auth response body is decoded.
	maxResponseBytes = 1 << 20
	// drainBytes caps how much of a leftover body is read before close so the
	// connection stays eligible for keep-alive reuse.
	drainBytes = 4096
)

// AuthInfo is the subset of the /1/auth response we use.
type AuthInfo struct {
	Type         string `json:"type"`
	APIKeyAccess struct {
		Events bool `json:"events"`
	} `json:"api_key_access"`
	Environment struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	} `json:"environment"`
	Team struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	} `json:"team"`
}

// Client calls the Honeycomb auth endpoint.
type Client struct {
	base       string
	transport  *http.Transport
	httpClient *http.Client
}

// New builds a Client for the given API base (e.g. https://api.honeycomb.io).
// The endpoint is validated by Config.Validate before this is called.
func New(endpoint string, timeout time.Duration) *Client {
	// A dedicated transport (rather than the shared http.DefaultTransport)
	// keeps a warm connection pool to the single API host across lookup
	// bursts and lets Shutdown release it.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConnsPerHost = 16
	return &Client{
		base:      strings.TrimRight(endpoint, "/"),
		transport: transport,
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			// Never follow redirects: the request carries the ingest key in a
			// custom header, which Go would forward to the redirect target.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Close releases idle connections held by the client's transport.
func (c *Client) Close() {
	c.transport.CloseIdleConnections()
}

// Lookup validates apiKey against /1/auth. Returns ErrInvalidKey on 401, a
// transient error on transport failure or non-200, or the decoded AuthInfo.
func (c *Client) Lookup(ctx context.Context, apiKey string) (*AuthInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/1/auth", nil)
	if err != nil {
		return nil, fmt.Errorf("building /1/auth request: %w", err)
	}
	req.Header.Set(authKeyHeader, apiKey)
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending /1/auth request: %w", err)
	}
	defer func() {
		// Drain whatever is left (401s have no body we care about; Decode
		// stops at the first JSON value) so the connection can be reused.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, drainBytes))
		_ = resp.Body.Close()
	}()

	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return nil, ErrInvalidKey
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("unexpected status %d from /1/auth", resp.StatusCode)
	}

	var info AuthInfo
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&info); err != nil {
		return nil, fmt.Errorf("decoding /1/auth response: %w", err)
	}
	return &info, nil
}
