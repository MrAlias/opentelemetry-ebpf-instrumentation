// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"debug/elf"
	"errors"
	"fmt"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

type RuntimeMetricSymbols struct {
	MemstatsAddr         uint64
	GCControllerAddr     uint64
	GOMAXPROCSAddr       uint64
	WorkAddr             uint64
	SizeClassToSizesAddr uint64
}

const (
	runtimeMetricSizeClassToSizesSymbol         = "runtime.class_to_size"
	runtimeMetricInternalSizeClassToSizesSymbol = "internal/runtime/gc.SizeClassToSize"
)

// ResolveRuntimeMetricSymbols resolves Go runtime global variables to absolute
// process addresses. Userspace provides only this metadata; BPF still reads the
// actual runtime metric values from the target process memory.
func ResolveRuntimeMetricSymbols(file, exactOwner *exec.FileInfo) (RuntimeMetricSymbols, error) {
	if file == nil || file.ELF() == nil {
		return RuntimeMetricSymbols{}, errors.New("missing executable file info")
	}
	if exactOwner == nil {
		return RuntimeMetricSymbols{}, errors.New("missing exact process owner")
	}

	loadBias, err := runtimeMetricLoadBias(exactOwner, file.Dev(), file.Ino())
	if err != nil {
		return RuntimeMetricSymbols{}, fmt.Errorf("reading executable load bias: %w", err)
	}

	return resolveRuntimeMetricSymbols(file.ELF(), loadBias)
}

func runtimeMetricLoadBias(
	exactOwner *exec.FileInfo,
	expectedDev, expectedIno uint64,
) (uint64, error) {
	if err := validateRuntimeMetricExecutableIdentity(
		exactOwner,
		expectedDev,
		expectedIno,
	); err != nil {
		return 0, err
	}
	if exactOwner.ProcessStartTime() == 0 {
		return procs.FindExeLoadBias(exactOwner.Pid())
	}

	var loadBias uint64
	err := exactOwner.UseProcessHandle(func(fd int) error {
		if err := validateRuntimeMetricOwner(fd, exactOwner); err != nil {
			return fmt.Errorf("before load-bias resolution: %w", err)
		}
		var err error
		loadBias, err = procs.FindExeLoadBiasFromProcFD(fd, expectedDev, expectedIno)
		if err != nil {
			return err
		}
		if err := validateRuntimeMetricOwner(fd, exactOwner); err != nil {
			return fmt.Errorf("after load-bias resolution: %w", err)
		}
		return nil
	})
	return loadBias, err
}

func validateRuntimeMetricExecutableIdentity(
	exactOwner *exec.FileInfo,
	expectedDev, expectedIno uint64,
) error {
	if expectedDev == 0 || expectedIno == 0 {
		return fmt.Errorf(
			"symbol-source executable identity is incomplete: dev=%d inode=%d",
			expectedDev,
			expectedIno,
		)
	}
	if exactOwner.Dev() == 0 || exactOwner.Ino() == 0 {
		return fmt.Errorf(
			"exact owner executable identity is incomplete: dev=%d inode=%d",
			exactOwner.Dev(),
			exactOwner.Ino(),
		)
	}
	if exactOwner.Dev() != expectedDev || exactOwner.Ino() != expectedIno {
		return fmt.Errorf(
			"symbol-source executable identity dev=%d inode=%d does not match exact owner dev=%d inode=%d",
			expectedDev,
			expectedIno,
			exactOwner.Dev(),
			exactOwner.Ino(),
		)
	}
	return nil
}

func resolveRuntimeMetricSymbols(f *elf.File, loadBias uint64) (RuntimeMetricSymbols, error) {
	const (
		memstatsSymbol     = "runtime.memstats"
		gcControllerSymbol = "runtime.gcController"
		gomaxprocsSymbol   = "runtime.gomaxprocs"
		workSymbol         = "runtime.work"
	)

	symbols, err := procs.FindExeSymbols(f, []string{
		memstatsSymbol,
		gcControllerSymbol,
		gomaxprocsSymbol,
		workSymbol,
		runtimeMetricSizeClassToSizesSymbol,
		runtimeMetricInternalSizeClassToSizesSymbol,
	}, elf.STT_OBJECT)
	if err != nil {
		return RuntimeMetricSymbols{}, err
	}

	memstats, ok := symbols[memstatsSymbol]
	if !ok {
		return RuntimeMetricSymbols{}, fmt.Errorf("runtime symbol %s not found", memstatsSymbol)
	}
	gcController, ok := symbols[gcControllerSymbol]
	if !ok {
		return RuntimeMetricSymbols{}, fmt.Errorf("runtime symbol %s not found", gcControllerSymbol)
	}
	gomaxprocs, ok := symbols[gomaxprocsSymbol]
	if !ok {
		return RuntimeMetricSymbols{}, fmt.Errorf("runtime symbol %s not found", gomaxprocsSymbol)
	}

	return RuntimeMetricSymbols{
		MemstatsAddr:         loadBias + memstats.Off,
		GCControllerAddr:     loadBias + gcController.Off,
		GOMAXPROCSAddr:       loadBias + gomaxprocs.Off,
		WorkAddr:             runtimeMetricSymbolAddr(symbols, workSymbol, loadBias),
		SizeClassToSizesAddr: runtimeMetricSymbolAddr(symbols, runtimeMetricSizeClassToSizesSymbol, loadBias),
	}, nil
}

func runtimeMetricSymbolAddr(symbols map[string]procs.Sym, name string, loadBias uint64) uint64 {
	if sym, ok := symbols[name]; ok {
		return loadBias + sym.Off
	}
	if name == runtimeMetricSizeClassToSizesSymbol {
		if sym, ok := symbols[runtimeMetricInternalSizeClassToSizesSymbol]; ok {
			return loadBias + sym.Off
		}
	}
	return 0
}
