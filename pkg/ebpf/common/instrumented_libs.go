// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"fmt"
	"io"
	"log/slog"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
)

type LibModule struct {
	References uint64
	Closers    []io.Closer
}

// Hold onto identities of files that are already instrumented, e.g. libssl.so.3.
type InstrumentedLibsT map[exec.FileID]*LibModule

func (libs InstrumentedLibsT) At(id exec.FileID) *LibModule {
	module, ok := libs[id]

	if !ok {
		module = &LibModule{References: 0}
		libs[id] = module
	}

	return module
}

func (libs InstrumentedLibsT) Find(id exec.FileID) *LibModule {
	module, ok := libs[id]

	if ok {
		return module
	}

	return nil
}

func (libs InstrumentedLibsT) AddRef(id exec.FileID) *LibModule {
	module := libs.At(id)
	module.References++

	return module
}

func (libs InstrumentedLibsT) RemoveRef(id exec.FileID) (*LibModule, error) {
	module := libs.Find(id)

	if module == nil {
		return nil, fmt.Errorf("attempt to remove reference of unknown module: device %d inode %d", id.Dev, id.Ino)
	}

	if module.References == 0 {
		return module, fmt.Errorf("attempt to remove reference of unreferenced module: device %d inode %d", id.Dev, id.Ino)
	}

	module.References--

	if module.References == 0 {
		for _, closer := range module.Closers {
			if err := closer.Close(); err != nil {
				slog.Debug("failed to close resource", "closer", closer, "error", err)
			}
		}

		delete(libs, id)
	}

	return module, nil
}
