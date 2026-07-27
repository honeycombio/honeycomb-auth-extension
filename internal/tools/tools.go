// Copyright Honeycomb
// SPDX-License-Identifier: Apache-2.0

//go:build tools

// Package tools pins build-tool dependencies (the opentelemetry-collector-contrib
// internal/tools pattern). This keeps tool-only modules out of the component
// module's dependency graph, which OCB distros consume.
package tools

import (
	_ "go.opentelemetry.io/collector/cmd/mdatagen"
)
