// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent // import "go.opentelemetry.io/obi/pkg/internal/cpython/agent"

import (
	_ "embed"
	"fmt"
	"strconv"
)

//go:embed httpx_agent.py
var source string

func bootstrap(ack uint64) string {
	// PyRun_SimpleString must return success to the pending-call dispatcher,
	// including when the application has an unsupported HTTPX installation.
	code := fmt.Sprintf(`try:
    import ctypes, sys
    status = 2
    if sys.implementation.name == "cpython" and object.__basicsize__ == 16 and not hasattr(sys, "gettotalrefcount") and not hasattr(sys, "getobjects") and (not hasattr(sys, "_is_gil_enabled") or sys._is_gil_enabled()):
        namespace = {"__name__": "_obi_httpx"}
        exec(%s, namespace)
        status = 1 if namespace["install"]() else 2
except BaseException:
    status = 3
finally:
    try:
        __import__("ctypes").c_ubyte.from_address(%d).value = status
    except BaseException:
        pass
`, strconv.Quote(source), ack)
	return "exec(" + strconv.Quote(code) + ", {})\n"
}
