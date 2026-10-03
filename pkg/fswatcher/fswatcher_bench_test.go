// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fswatcher

import (
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// benchTree creates nFiles regular files of distinct sizes and contents,
// half directly tracked and half inside a tracked directory (with one level of
// subdirectories), mirroring a Kubernetes secret/configmap mount.
func benchTree(b *testing.B, nFiles int) []string {
	b.Helper()
	root := b.TempDir()
	dir := filepath.Join(root, "mount")
	r := rand.New(rand.NewPCG(uint64(nFiles), 42))
	var tracked []string
	for i := range nFiles {
		var p string
		if i%2 == 0 {
			p = filepath.Join(root, fmt.Sprintf("file-%03d.pem", i))
			tracked = append(tracked, p)
		} else {
			p = filepath.Join(dir, fmt.Sprintf("sub-%d", i%4), fmt.Sprintf("key-%03d", i))
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			b.Fatal(err)
		}
		// Sizes from 256 B to ~48 KiB, so both small and multi-buffer reads
		// are exercised.
		data := make([]byte, 256+r.IntN(48<<10))
		for j := range data {
			data[j] = byte(r.Uint32())
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			b.Fatal(err)
		}
	}
	return append(tracked, dir)
}

// BenchmarkWatcherTick measures one polling pass of (*Watcher).tick over a
// set of unchanged files (the steady state of the agent's certificate and
// config watchers), which stats and checksums every tracked file.
func BenchmarkWatcherTick(b *testing.B) {
	logger := slog.New(slog.DiscardHandler)
	for _, n := range []int{8, 64} {
		b.Run(fmt.Sprintf("files=%d", n), func(b *testing.B) {
			tracked := benchTree(b, n)
			// A long interval keeps the background loop idle so that tick
			// is only driven by the benchmark.
			w, err := New(logger, tracked, WithInterval(time.Hour))
			if err != nil {
				b.Fatal(err)
			}
			defer w.Close()
			w.silent.Store(true)
			b.ReportAllocs()
			for b.Loop() {
				w.tick()
			}
		})
	}
}
