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
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrInvalidKey means /1/auth returned 401: the key is invalid or revoked.
// It is distinct from transient/transport errors so the caller can decide
// fail-open vs fail-closed, and so only invalid keys are negatively cached.
var ErrInvalidKey = errors.New("honeycomb api key is invalid")

// authKeyHeader is the header /1/auth expects the key on. This is fixed
// regardless of which inbound header the client used to send the key.
const authKeyHeader = "x-honeycomb-team"

// AuthInfo is the subset of the /1/auth response we use.
type AuthInfo struct {
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
	httpClient *http.Client
}

// New builds a Client for the given API base (e.g. https://api.honeycomb.io).
func New(endpoint string, timeout time.Duration) (*Client, error) {
	if _, err := url.Parse(endpoint); err != nil {
		return nil, fmt.Errorf("invalid endpoint %q: %w", endpoint, err)
	}
	return &Client{
		base:       strings.TrimRight(endpoint, "/"),
		httpClient: &http.Client{Timeout: timeout},
	}, nil
}

// Lookup validates apiKey against /1/auth. Returns ErrInvalidKey on 401, a
// transient error on transport failure or non-2xx, or the decoded AuthInfo.
func (c *Client) Lookup(ctx context.Context, apiKey string) (*AuthInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/1/auth", nil)
	if err != nil {
		return nil, fmt.Errorf("building /1/auth request: %w", err)
	}
	req.Header.Set(authKeyHeader, apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending /1/auth request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return nil, ErrInvalidKey
	case resp.StatusCode > 299:
		return nil, fmt.Errorf("unexpected status %d from /1/auth", resp.StatusCode)
	}

	var info AuthInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decoding /1/auth response: %w", err)
	}
	return &info, nil
}
