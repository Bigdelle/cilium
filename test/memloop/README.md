# Offline memloop memory scenarios

In-process Go benchmarks that mirror the memloop GKE workloads. They give cheap
memory signals without a cluster:

- `B/op` and `allocs/op`: transient allocation churn (`-benchmem`).
- `inuse-B/op`: post-GC retained heap. It is measured as `runtime.GC()` x2 +
  `runtime.ReadMemStats().HeapAlloc` before and after the measured work,
  divided by `b.N`.

All benchmarks are named `BenchmarkMemloopScenario_*`. They live next to the
code they stress, as internal `package X` test files called
`memloop_scenario*_bench_test.go`. Each one is deterministic: fixed seeds, no
network, no BPF or root, no sleeps. Each finishes in well under 10s with
`-benchtime=1x`.

`scenarios.json` is the machine-readable list that memloop consumes (for
example `memloop-scenarios -offline -workload=dns -cilium=.` runs every
scenario that mirrors the `dns` GKE workload, and `-workload=dns-inuse` only
the `_Inuse` ones). Each entry
has `name`, `gke_workload`, `package`, `bench_regex`, `hot_packages` and
`inuse`. `inuse: true` marks the `_Inuse` variants. These grow retained state
across iterations with no teardown, so `inuse-B/op` is the retained heap per
wave.

## Running

```sh
# all scenarios, results in /tmp/memloop-offline
test/memloop/run-offline-scenarios.sh

# filter by scenario name (extended regex), more iterations, heap profiles
BENCHTIME=3x COUNT=5 MEMPROFILE=1 OUT=/tmp/ml test/memloop/run-offline-scenarios.sh '^cidr-policy'

# a single package directly
go test ./pkg/fqdn/namemanager/ -run='^$' -bench='^BenchmarkMemloopScenario_' -benchtime=1x -benchmem
```

The script writes these files to `$OUT`:

- `<name>.txt`: raw output.
- `results.txt`: all `Benchmark*` lines.
- `summary.tsv`: name, benchmark, ns/op, B/op, allocs/op, inuse-B/op.
- With `MEMPROFILE=1`: `<name>.memprofile` and `<name>.test`, for use with
  `go tool pprof -sample_index=alloc_space <name>.test <name>.memprofile`.

> `inuse-B/op` of churn (non-`_Inuse`) benchmarks includes one-time warm-up
> costs, such as lazily grown maps, regexp LRU or statedb caches, so it shrinks
> roughly as `1/b.N`. Compare it only at a fixed `-benchtime`. `B/op` and
> `allocs/op` are stable to about 1%. `ns/op` is noisy and is not the target
> signal.

## Scenarios

### dns

- **GKE workload:** `dns`. Clients resolve 500 wave-indexed names
  (`svc-NNN.wave-W.memloop.test`), each with 4 IPs. toFQDNs `matchName` and
  `matchPattern` selectors select them, and IPs rotate every wave.
- **Package:** `./pkg/fqdn/namemanager`
- **Benchmarks:**
  - `BenchmarkMemloopScenario_DNS`: 4 waves per op. Each wave registers
    selectors, resolves names, does lookups, rotates IPs, then runs a
    synthetic-clock GC with zombies and 10% alive connections. Finally it
    unregisters the previous wave's selectors.
  - `BenchmarkMemloopScenario_DNS_Inuse`: one new wave per op, nothing
    removed.
- **Hot functions:**
  - `namemanager`: `RegisterFQDNSelector`, `UnregisterFQDNSelector`,
    `UpdateGenerateDNS`, `updateDNSIPs`, `deriveLabelsForName(s)`,
    `mapSelectorsToNamesLocked`, `updateMetadata`, `maybeRemoveMetadata`.
  - `fqdn.DNSCache`: `Update`, `Lookup`, `LookupIP`, `LookupByRegexp`, `GC`,
    `ReplaceFromCacheByNames`, `RemoveKnown`.
  - `DNSZombieMappings`: `Upsert`, `MarkAlive`, `GC`.
  - `matchpattern`, and the `re` compile LRU.
- **Not covered:** `pkg/fqdn/dnsproxy` needs real sockets. The ipcache is the
  `testipcache` mock.
- **Command:**

  ```sh
  go test ./pkg/fqdn/namemanager/ -run='^$' -bench='^BenchmarkMemloopScenario_DNS' -benchtime=1x -benchmem
  ```

### service-lb

- **GKE workload:** `service-lb`. 150 ClusterIP services with 3 named ports
  each. Backends churn in waves, with 6–12 of 12 pods active.
- **Package:** `./pkg/loadbalancer/writer`. It reuses the writer test hive
  `fixture`.
- **Benchmarks:**
  - `BenchmarkMemloopScenario_ServiceLB`: upsert, then 4 churn waves, then
    teardown.
  - `BenchmarkMemloopScenario_ServiceLB_Inuse`: one new namespace of 150x3
    services per op, with no teardown.
- **Hot functions:**
  - `Writer`: `UpsertServiceAndFrontends`, `SetBackends`/`SetBackendsOfCluster`,
    `updateBackends`, `RefreshFrontends`, `DefaultSelectBackends`,
    `DeleteServiceAndFrontends`, `DeleteBackendsOfService`.
  - statedb `WriteTxn`, and part radix tree cloning.
- **Command:**

  ```sh
  go test ./pkg/loadbalancer/writer/ -run='^$' -bench='^BenchmarkMemloopScenario_' -benchtime=1x -benchmem
  ```

### cidr-policy

- **GKE workload:** `cidr-policy`. 25 CNPs per wave. Each has an egress
  toCIDRSet of 5 `/20` blocks with 22 `/28` `except` holes, which gives
  2,875 prefixes per wave. Each wave replaces the previous one.
- **Packages:**
  - `./pkg/policy` (policy half).
  - `./pkg/ipcache` (ipcache half).
- **Benchmarks:**
  - `BenchmarkMemloopScenario_CIDRPolicy`: 3 waves on a fresh repository.
    `ReplaceByResource`, CIDR identities into the SelectorCache,
    resolve + `DistillPolicy`, then remove the previous wave.
  - `BenchmarkMemloopScenario_CIDRPolicy_Inuse`: one new wave per op, with no
    removal.
  - `BenchmarkMemloopScenario_CIDRPolicy_IPCache`: 3 waves of
    `UpsertMetadataBatch` (CIDR labels, `IsCIDR`) and label injection, then
    prune the previous wave. The last wave is pruned too, so `inuse-B/op` is
    the residue after full teardown.
  - `BenchmarkMemloopScenario_CIDRPolicy_IPCache_Inuse`: one new wave of
    2,875 prefixes per op, with no pruning.
- **Hot functions:**
  - Policy: `policyutils.RulesToPolicyEntries` (CIDRSet/except to selectors),
    `policy.GetCIDRPrefixes`, `Repository.ReplaceByResource`,
    `SelectorCache.AddSelectors`/`UpdateIdentities`, `types.CIDRSelector.Matches`,
    `resolvePolicyLocked`, `DistillPolicy`, `labels.GetCIDRLabels`.
  - IPCache: `UpsertMetadataBatch`/`RemoveMetadataBatch`, `prefixRefCounter`,
    `metadata.upsertLocked`/`remove`, `InjectLabels`, `resolveIdentity`,
    `upsertLocked`/`deleteLocked`.
- **Command:**

  ```sh
  go test ./pkg/policy/ -run='^$' -bench='^BenchmarkMemloopScenario_CIDRPolicy' -benchtime=1x -benchmem
  go test ./pkg/ipcache/ -run='^$' -bench='^BenchmarkMemloopScenario_' -benchtime=1x -benchmem
  ```

### k8s-crd

- **GKE workload:** `k8s-crd`. 1000 pods with 25 labels and 15 annotations
  each, their CEPs, 100 CNPs and 50 KNPs. 4 waves each replace half of the
  pods and re-parse a quarter of the policies.
- **Package:** `./pkg/k8s`
- **Benchmarks:**
  - `BenchmarkMemloopScenario_K8sCRD`: transient allocations only.
  - `BenchmarkMemloopScenario_K8sCRD_Inuse`: the agent-side caches are
    retained.
- **Hot functions:**
  - Pods: `GetPodMetadata` (`SanitizePodLabels`, ObjectMeta deepcopy),
    `labels.Map2Labels`, `labelsfilter.Filter`,
    `Labels.SortedList`/`LabelArray`.
  - CEPs: `TransformToCiliumEndpoint`, `ConvertCEPToCoreCEP`,
    `ConvertCoreCiliumEndpointToTypesCiliumEndpoint`.
  - Policies: `CiliumNetworkPolicy.Parse`, `ParseNetworkPolicy`.
- **Command:**

  ```sh
  go test ./pkg/k8s/ -run='^$' -bench='^BenchmarkMemloopScenario_' -benchtime=1x -benchmem
  ```

### endpoint-scale

- **GKE workload:** `endpoint-scale` (memloop). Every wave creates 40
  policy-selected pods (20 per worker, bounded `eps-group` label set so
  identities are reused) next to 4 long-lived anchors, waits for endpoint
  regeneration, then deletes them. `endpoint-scale-inuse` adds 6 pods per wave
  and never deletes them. The offline benchmark scales 0 → 60 → 0 endpoints.
- **Package:** `./pkg/policy`
- **Benchmark:** `BenchmarkMemloopScenario_EndpointScale`. Each op runs one
  0 → 60 → 0 wave. It also reports `peak-mapentries`.
- **Hot functions:**
  - SelectorCache: `UpdateIdentities`, `queueUserNotification`,
    `queueNotifiedUsersCommit`.
  - Policy computation: `Repository.ComputeSelectorPolicy`, `DistillPolicy`,
    `makeL4PolicyMap`.
  - Incremental updates: `L4Policy.AccumulateMapChanges`,
    `EndpointPolicy.ConsumeMapChanges`, `mapState.upsert` and
    `mapState.deleteExistingWithChanges`.
- **Not covered:** the endpoint manager, BPF and proxy. Policy computation is
  done the way endpoint regeneration does it.
- **Command:**

  ```sh
  go test ./pkg/policy/ -run='^$' -bench='^BenchmarkMemloopScenario_EndpointScale' -benchtime=1x -benchmem
  ```

### identity-churn

- **GKE workload:** `identity-churn` (memloop). Every wave relabels 20 pods
  with a globally unique `id-gen` label (20 new security identities per wave,
  the previous wave's identities are released), under CNPs whose
  `matchExpressions` must be evaluated against every new identity.
  `identity-churn-inuse` adds 8 uniquely-labelled pods per wave and never
  deletes them. The offline benchmark allocates and releases waves of 500
  unique label sets.
- **Package:** `./pkg/identity/cache`. It uses CRD identity mode on the fake
  clientset, and the owner forwards identities into a real SelectorCache.
- **Benchmarks:**
  - `BenchmarkMemloopScenario_IdentityChurn`: allocate, release, then
    simulated operator GC.
  - `BenchmarkMemloopScenario_IdentityChurn_Inuse`: identities are retained
    across waves.
- **Hot functions:**
  - `CachingIdentityAllocator.AllocateIdentity`/`Release`.
  - `allocator.Allocate`/`Release`.
  - `crdBackend.AllocateID`/`ListAndWatch`.
  - `SelectorCache.UpdateIdentities`.
- **Not covered:** the kvstore backend. It needs etcd, and the in-memory
  kvstore client does not implement `LockPath`. About 25–35% of allocations
  come from the fake clientset.
- **Command:**

  ```sh
  go test ./pkg/identity/cache/ -run='^$' -bench='^BenchmarkMemloopScenario_' -benchtime=1x -benchmem
  ```
