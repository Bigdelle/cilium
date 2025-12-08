// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resourcewait

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/redirectpolicy"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func waitForResources(
	ctx context.Context,
	logger *slog.Logger,
	db *statedb.DB,
	lrps statedb.Table[*redirectpolicy.LocalRedirectPolicy],
	services statedb.Table[*loadbalancer.Service],
	resources []string,
) error {
	var lrpIDs []loadbalancer.ServiceName

	for _, res := range resources {
		parts := strings.Split(res, "/")
		if len(parts) != 3 {
			return fmt.Errorf("invalid resource format %q, expected kind/namespace/name", res)
		}
		kind, namespace, name := parts[0], parts[1], parts[2]

		if kind != "CiliumLocalRedirectPolicy" {
			logger.Warn("Only CiliumLocalRedirectPolicy is supported for resource waiting", logfields.Kind, kind)
			continue
		}

		lrpIDs = append(lrpIDs, loadbalancer.NewServiceName(namespace, name))
	}

	if len(lrpIDs) == 0 {
		return nil
	}

	logger.Info("Waiting for CLRP resources", logfields.Count, len(lrpIDs))

	for {
		txn := db.ReadTxn()
		iter, watchLRPs := lrps.AllWatch(txn)
		_, watchServices := services.AllWatch(txn)

		foundIDs := make(map[string]*redirectpolicy.LocalRedirectPolicy)

		for obj := range iter {
			for _, id := range lrpIDs {
				// Match by Namespace and Name (ID)
				if obj.ID.String() == id.String() {
					foundIDs[id.String()] = obj
				}
			}
		}

		readyCount := 0
		for _, id := range lrpIDs {
			lrp, found := foundIDs[id.String()]
			if !found {
				continue
			}

			// Check if the pseudo-service exists
			svcName := lrp.RedirectServiceName()
			if _, _, found := services.Get(txn, loadbalancer.ServiceByName(svcName)); found {
				readyCount++
			}
		}

		if readyCount == len(lrpIDs) {
			logger.Info("All required CLRP resources found and services created")
			return nil
		}

		// Log missing resources occasionally?
		// For now, just wait.
		logger.Debug("Waiting for CLRP resources", "found", len(foundIDs), "ready", readyCount, "required", len(lrpIDs))

		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for CLRP resources: %w", ctx.Err())
		case <-watchLRPs:
			continue
		case <-watchServices:
			continue
		case <-time.After(5 * time.Second):
			// Periodic check just in case, though watch should handle it.
			continue
		}
	}
}
