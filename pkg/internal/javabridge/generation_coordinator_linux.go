// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package javabridge // import "go.opentelemetry.io/obi/pkg/internal/javabridge"

import "sync"

// GenerationCoordinator excludes userspace cleanup while a Java bridge request
// can own or mutate generation state. Every userspace handler and Cleanup that
// shares one internal map set must share this coordinator. BPF producers use
// their map fences and post-publication revalidation instead of this
// process-local lock.
type GenerationCoordinator struct {
	mu sync.RWMutex
}

func NewGenerationCoordinator() *GenerationCoordinator {
	return &GenerationCoordinator{}
}

func (c *GenerationCoordinator) tryLockHandler() (func(), bool) {
	if c == nil {
		panic("nil Java generation coordinator")
	}
	if !c.mu.TryRLock() {
		return nil, false
	}
	return c.mu.RUnlock, true
}

func (c *GenerationCoordinator) lockCleanup() func() {
	if c == nil {
		panic("nil Java generation coordinator")
	}
	c.mu.Lock()
	return c.mu.Unlock
}
