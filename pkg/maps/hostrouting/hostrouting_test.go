/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright Authors of Cilium */

package hostrouting

import (
	"log/slog"
	"net/netip"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
)

func TestHostRoutingMaps(t *testing.T) {
	logger := slog.Default()
	
	// Set up a temporary directory for BPF maps
	tmpDir, err := os.MkdirTemp("", "cilium_host_routing_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)
	
	bpf.CheckAndMountPrivileged(tmpDir)

	// Initialize maps
	err = InitMaps(logger)
	require.NoError(t, err)

	// Test CIDR updates
	cidrs := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("fd00::/16"),
	}
	err = UpdateCIDRs(logger, cidrs)
	require.NoError(t, err)
}
