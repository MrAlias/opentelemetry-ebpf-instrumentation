// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/obi/pkg/internal/pythonagent"
)

const pythonInjectionQueueLen = 100

func newPythonInjectionQueue(
	log *slog.Logger,
	slot injectionSlot,
	inject func(context.Context, pythonagent.InjectionTarget),
) *injectionQueue[pythonagent.InjectionTarget] {
	return newInjectionQueue(log, "python", slot, pythonInjectionQueueLen, inject, nil)
}
