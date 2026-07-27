// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"time"
)

func main() {
	fmt.Printf("obi-windows-target.exe PID=%d\n", os.Getpid())
	time.Sleep(3 * time.Second)
}
