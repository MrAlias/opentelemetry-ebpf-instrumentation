// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package javabridge // import "go.opentelemetry.io/obi/pkg/internal/javabridge"

import (
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/ebpf/timing"
)

// ErrProcessCapabilityRetired reports that the requested capability crossed a
// durable retirement boundary and must never be reused. Callers must generate
// a fresh capability before attaching or reconfiguring the Java agent.
var ErrProcessCapabilityRetired = errors.New("java process capability is retired")

// ErrProcessClaimContended reports that a finite BPF publisher currently owns
// P(process). Callers can retry without changing authorization state.
var ErrProcessClaimContended = errors.New("java process claim is contended")

type processAuthorizationMaps struct {
	authorized   cleanupMap
	incarnations cleanupMap
	claims       cleanupMap
	retired      cleanupMap
}

// AuthorizeProcessCapability serializes an enabled-bridge authorization with
// retirement cleanup and every BPF ancestry publisher. Only the Java agent's
// PROCESS_REGISTER operation may install an incarnation. In particular, this
// helper never revives an incarnation whose retirement marker is still live:
// that marker remains a one-way barrier until cleanup proves that every exact
// carrier and replay reference is gone.
func AuthorizeProcessCapability(
	maps Maps,
	process Identity,
	capability uint64,
) (bool, error) {
	wrap := func(m *ebpf.Map) cleanupMap {
		if m == nil {
			return nil
		}
		return kernelCleanupMap{Map: m}
	}
	if !javaProcessClaimCoordinator.TryLock() {
		return false, ErrProcessClaimContended
	}
	defer javaProcessClaimCoordinator.Unlock()
	return authorizeProcessCapability(processAuthorizationMaps{
		authorized:   wrap(maps.Authorized),
		incarnations: wrap(maps.Incarnations),
		claims:       wrap(maps.ThreadMappingClaims),
		retired:      wrap(maps.Retired),
	}, process, capability, timing.MonoTimeNow())
}

// DeauthorizeProcessCapability removes only the exact authorization issued to
// one Java process. When removeIncarnation is false, the exact incarnation is
// deliberately retained as durable userspace-cleanup authority: after the
// authorization is absent, cleanup can acquire P(process), publish R(A), and
// only then delete A. The disabled bridge has no remote carriers or retirement
// sweeper, so its caller requests an exact incarnation deletion as well.
func DeauthorizeProcessCapability(
	maps Maps,
	process Identity,
	capability uint64,
	removeIncarnation bool,
) error {
	wrap := func(m *ebpf.Map) cleanupMap {
		if m == nil {
			return nil
		}
		return kernelCleanupMap{Map: m}
	}
	javaProcessClaimCoordinator.Lock()
	defer javaProcessClaimCoordinator.Unlock()
	return deauthorizeProcessCapability(processAuthorizationMaps{
		authorized:   wrap(maps.Authorized),
		incarnations: wrap(maps.Incarnations),
	}, process, capability, removeIncarnation)
}

// SuspendProcessAuthorization fail-closes an unconfirmed exact capability
// before its corresponding Java attachment is declined. A concurrently
// confirmed replacement remains untouched.
func SuspendProcessAuthorization(
	maps Maps,
	process Identity,
	capability uint64,
) error {
	if maps.Authorized == nil {
		return errors.New("java process authorization map is missing")
	}
	if process.PID == 0 || process.TID != process.PID || capability == 0 {
		return errors.New("java process authorization identity is invalid")
	}
	javaProcessClaimCoordinator.Lock()
	defer javaProcessClaimCoordinator.Unlock()
	authorized := kernelCleanupMap{Map: maps.Authorized}
	_, err := cleanupDeleteExactOrCommitted(authorized, process, capability)
	if err != nil {
		return fmt.Errorf("suspending exact Java process authorization: %w", err)
	}
	return nil
}

func authorizeProcessCapability(
	maps processAuthorizationMaps,
	process Identity,
	capability uint64,
	now time.Duration,
) (authorized bool, result error) {
	if maps.authorized == nil || maps.claims == nil || maps.retired == nil {
		return false, errors.New("java process authorization maps are incomplete")
	}
	if process.PID == 0 || process.TID != process.PID || capability == 0 ||
		capability&(uint64(1)<<63) != 0 || now <= 0 {
		return false, errors.New("java process authorization identity is invalid")
	}

	retirement := retiredProcessKey{
		Process: process, ProcessIncarnation: capability,
	}
	var observed uint64
	retirementErr := maps.retired.Lookup(&retirement, &observed)
	if retirementErr == nil {
		return false, ErrProcessCapabilityRetired
	}
	if !errors.Is(retirementErr, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf(
			"looking up Java process retirement before authorization: %w", retirementErr,
		)
	}

	claim, valid := javaRemoteParentProcessCleanupClaim(now, process, capability)
	if !valid {
		return false, errors.New("creating Java process authorization claim")
	}
	updateErr := maps.claims.Update(&process, &claim, ebpf.UpdateNoExist)
	if errors.Is(updateErr, ebpf.ErrKeyExist) {
		return false, ErrProcessClaimContended
	}
	var installed threadMappingClaimValue
	lookupErr := maps.claims.Lookup(&process, &installed)
	if lookupErr != nil || installed != claim {
		// A successful insertion with an unreadable readback may have left our
		// tagged P installed. Do not guess or delete a foreign replacement;
		// Cleanup recognizes the tag and recovers it on a later sweep.
		if updateErr == nil {
			if lookupErr != nil {
				return false, fmt.Errorf(
					"revalidating Java process authorization claim: %w", lookupErr,
				)
			}
			return false, errors.New("revalidating acquired Java process authorization claim")
		}
		if lookupErr != nil && !errors.Is(lookupErr, ebpf.ErrKeyNotExist) {
			return false, errors.Join(
				fmt.Errorf("acquiring Java process authorization claim: %w", updateErr),
				fmt.Errorf("revalidating Java process authorization claim: %w", lookupErr),
			)
		}
		return false, fmt.Errorf("acquiring Java process authorization claim: %w", updateErr)
	}
	if updateErr != nil {
		result = errors.Join(result, fmt.Errorf(
			"acquiring Java process authorization claim: %w", updateErr,
		))
	}
	releaseClaim := true
	defer func() {
		if !releaseClaim {
			return
		}
		_, releaseErr := cleanupDeleteExactOrCommitted(maps.claims, process, claim)
		if releaseErr != nil {
			result = errors.Join(result, fmt.Errorf(
				"releasing Java process authorization claim: %w", releaseErr,
			))
		}
	}()

	// sched_process_exit cannot take P. Recheck after acquisition so a target
	// epoch that retired between the optimistic read and this fence is never
	// re-authorized.
	retirementErr = maps.retired.Lookup(&retirement, &observed)
	if retirementErr == nil {
		return false, errors.Join(result, ErrProcessCapabilityRetired)
	}
	if !errors.Is(retirementErr, ebpf.ErrKeyNotExist) {
		return false, errors.Join(result, fmt.Errorf(
			"revalidating Java process retirement before authorization: %w", retirementErr,
		))
	}

	authorized, authorizationErr := setProcessAuthorization(
		maps.authorized, process, capability,
	)
	result = errors.Join(result, authorizationErr)
	if !authorized {
		// An update error plus an unreadable readback has unknown commit state.
		// Keep P closed until Cleanup recovers it; the caller must not attach and
		// retries the desired authorization rather than exposing old Q/I state.
		var current uint64
		if authorizationErr != nil &&
			maps.authorized.Lookup(&process, &current) != nil {
			releaseClaim = false
		}
		return false, result
	}

	retirementErr = maps.retired.Lookup(&retirement, &observed)
	if errors.Is(retirementErr, ebpf.ErrKeyNotExist) {
		return true, result
	}
	deleted, rollbackErr := cleanupDeleteExactOrCommitted(
		maps.authorized, process, capability,
	)
	if rollbackErr != nil || !deleted {
		releaseClaim = false
	}
	if retirementErr == nil {
		return false, errors.Join(result, ErrProcessCapabilityRetired, rollbackErr)
	}
	return false, errors.Join(result,
		fmt.Errorf("revalidating Java process retirement after authorization: %w", retirementErr),
		rollbackErr,
	)
}

func setProcessAuthorization(
	authorized cleanupMap,
	process Identity,
	capability uint64,
) (bool, error) {
	updateErr := authorized.Update(&process, &capability, ebpf.UpdateAny)
	if updateErr == nil {
		return true, nil
	}
	var current uint64
	lookupErr := authorized.Lookup(&process, &current)
	if lookupErr == nil && current == capability {
		return true, fmt.Errorf("updating Java process authorization: %w", updateErr)
	}
	if lookupErr != nil && !errors.Is(lookupErr, ebpf.ErrKeyNotExist) {
		return false, errors.Join(
			fmt.Errorf("updating Java process authorization: %w", updateErr),
			fmt.Errorf("revalidating Java process authorization: %w", lookupErr),
		)
	}
	return false, fmt.Errorf("updating Java process authorization: %w", updateErr)
}

func deauthorizeProcessCapability(
	maps processAuthorizationMaps,
	process Identity,
	capability uint64,
	removeIncarnation bool,
) error {
	if maps.authorized == nil || (removeIncarnation && maps.incarnations == nil) {
		return errors.New("java process deauthorization maps are incomplete")
	}
	if process.PID == 0 || process.TID != process.PID || capability == 0 {
		return errors.New("java process deauthorization identity is invalid")
	}

	var authorized uint64
	if err := maps.authorized.Lookup(&process, &authorized); err != nil {
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("looking up Java process authorization: %w", err)
		}
	} else {
		if authorized != capability {
			// A different exact Q is conclusive proof that this capability is
			// already unauthorized. Preserve the replacement. Disabled mode must
			// still continue to exact-delete I(A); otherwise an out-of-order A
			// deletion can leave a stale incarnation beside replacement Q(B).
			if !removeIncarnation {
				return nil
			}
		} else {
			deleted, err := cleanupDeleteExactOrCommitted(
				maps.authorized, process, capability,
			)
			if err != nil {
				return fmt.Errorf("deauthorizing Java process: %w", err)
			}
			if !deleted {
				return errors.New("java process authorization changed during deauthorization")
			}
		}
	}

	if !removeIncarnation {
		return nil
	}
	if _, err := cleanupDeleteExactOrCommitted(
		maps.incarnations, process, capability,
	); err != nil {
		return fmt.Errorf("deauthorizing Java process incarnation: %w", err)
	}
	return nil
}

func cleanupDeleteExactOrCommitted[K, V comparable](
	m lookupDeleteMap,
	key K,
	expected V,
) (bool, error) {
	deleted, err := cleanupDeleteExact(m, key, expected)
	if err == nil {
		return deleted, nil
	}
	var current V
	lookupErr := m.Lookup(&key, &current)
	if errors.Is(lookupErr, ebpf.ErrKeyNotExist) {
		return true, nil
	}
	if lookupErr != nil {
		return false, errors.Join(err, fmt.Errorf("revalidating exact deletion: %w", lookupErr))
	}
	return false, err
}
