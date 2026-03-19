/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright Authors of Cilium */

package hostrouting

import (
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/option"
)

// Cell provides the host routing maps and initializes them.
var Cell = cell.Module(
	"host-routing-map",
	"eBPF maps for selective host routing",

	cell.Invoke(func(lc cell.Lifecycle, logger *slog.Logger, cfg *option.DaemonConfig) {
		lc.Append(cell.Hook{
			OnStart: func(ctx cell.HookContext) error {
				if len(cfg.BPFHostRoutingCIDRs) == 0 {
					return nil
				}
				return Register(logger, cfg)
			},
		})
	}),
)
