/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright Authors of Cilium */

package hostrouting

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/cidrmap"
	"github.com/cilium/cilium/pkg/option"
)

const (
	MapNameV4  = "cilium_host_routing_v4"
	MapNameV6  = "cilium_host_routing_v6"
	MaxEntries = 16384
)

var (
	v4Map *cidrmap.CIDRMap
	v6Map *cidrmap.CIDRMap
)

// InitMaps initializes the host routing maps
func InitMaps(logger *slog.Logger) error {
	var err error
	v4Map, err = cidrmap.OpenMapElems(logger, bpf.MapPath(logger, MapNameV4), 32, true, MaxEntries)
	if err != nil {
		return fmt.Errorf("unable to open or create %s: %w", MapNameV4, err)
	}

	v6Map, err = cidrmap.OpenMapElems(logger, bpf.MapPath(logger, MapNameV6), 128, true, MaxEntries)
	if err != nil {
		return fmt.Errorf("unable to open or create %s: %w", MapNameV6, err)
	}

	return nil
}

// UpdateCIDRs updates the host routing maps with the given CIDRs
func UpdateCIDRs(logger *slog.Logger, prefixes []netip.Prefix) error {
	for _, prefix := range prefixes {
		ones := prefix.Bits()
		ip := prefix.Addr()
		cidr := net.IPNet{
			IP:   net.IP(ip.AsSlice()),
			Mask: net.CIDRMask(ones, ip.BitLen()),
		}

		if ip.Is4() {
			if v4Map == nil {
				continue
			}
			logger.Debug("Updating host routing v4 map", logfields.CIDR, cidr)
			if err := v4Map.InsertCIDR(cidr); err != nil {
				return fmt.Errorf("unable to insert %s into v4 map: %w", cidr, err)
			}
		} else {
			if v6Map == nil {
				continue
			}
			logger.Debug("Updating host routing v6 map", logfields.CIDR, cidr)
			if err := v6Map.InsertCIDR(cidr); err != nil {
				return fmt.Errorf("unable to insert %s into v6 map: %w", cidr, err)
			}
		}
	}
	return nil
}

// Register initializes the host routing maps and populates them from config
func Register(logger *slog.Logger, cfg *option.DaemonConfig) error {
	if err := InitMaps(logger); err != nil {
		return err
	}
	return UpdateCIDRs(logger, cfg.BPFHostRoutingCIDRs)
}
