// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resourcewait

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/redirectpolicy"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
)

// Cell provides the ResourceWait promise.
var Cell = cell.Module(
	"resource-wait",
	"Waits for specific Kubernetes resources to be ready",

	cell.Provide(newResourceWaitPromise),
	cell.Config(DefaultConfig),
)

type Config struct {
	// ResourceWaitList is a list of resources to wait for in the format kind/namespace/name.
	ResourceWaitList []string
	// ResourceWaitTimeout is the timeout for waiting for resources.
	ResourceWaitTimeout time.Duration
}

var DefaultConfig = Config{
	ResourceWaitList:    []string{},
	ResourceWaitTimeout: 5 * time.Minute,
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.StringSlice("resource-wait-list", def.ResourceWaitList, "List of resources to wait for in the format kind/namespace/name (e.g. CiliumLocalRedirectPolicy/default/my-policy)")
	flags.Duration("resource-wait-timeout", def.ResourceWaitTimeout, "Timeout for waiting for resources")
}

// ResourceWait is the value resolved by the promise.
type ResourceWait struct{}

type params struct {
	cell.In

	Logger   *slog.Logger
	JobGroup job.Group
	DB       *statedb.DB
	LRPs     statedb.Table[*redirectpolicy.LocalRedirectPolicy]
	Services statedb.Table[*loadbalancer.Service]
	Config   Config
}

func newResourceWaitPromise(p params) promise.Promise[ResourceWait] {
	resolver, prom := promise.New[ResourceWait]()

	if len(p.Config.ResourceWaitList) == 0 {
		resolver.Resolve(ResourceWait{})
		return prom
	}

	p.JobGroup.Add(job.OneShot("resource-wait", func(ctx context.Context, health cell.Health) error {
		// Create a context with timeout
		ctx, cancel := context.WithTimeout(ctx, p.Config.ResourceWaitTimeout)
		defer cancel()

		if err := waitForResources(ctx, p.Logger, p.DB, p.LRPs, p.Services, p.Config.ResourceWaitList); err != nil {
			resolver.Reject(err)
			return fmt.Errorf("failed to wait for resources: %w", err)
		}

		resolver.Resolve(ResourceWait{})
		return nil
	}))

	return prom
}
