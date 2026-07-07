// Copyright Honeycomb
// SPDX-License-Identifier: Apache-2.0

// Package honeycombauthextension is an OpenTelemetry Collector server
// authenticator extension that validates the incoming x-honeycomb-team ingest
// key against Honeycomb's /1/auth endpoint, caches the result, and optionally
// injects the resolved team/environment into client.Info.Auth for downstream
// components.
package honeycombauthextension // import "github.com/honeycombio/honeycomb-auth-extension/honeycombauthextension"
