// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package model

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
)

func TestCreateModelFromLabelArrayMatchesCreateModel(t *testing.T) {
	for name, lblArray := range map[string]labels.LabelArray{
		"nil":      nil,
		"empty":    {},
		"single":   labels.ParseLabelArray("k8s:app=frontend"),
		"multiple": labels.ParseLabelArray("k8s:app=frontend", "any:env=prod", "reserved:host"),
	} {
		t.Run(name, func(t *testing.T) {
			id := identity.NewIdentityFromLabelArray(1234, lblArray)
			require.Equal(t, CreateModel(id), CreateModelFromLabelArray(1234, lblArray))
		})
	}
}

var sinkIdentityModels []*models.Identity

func BenchmarkCreateModelPerCachedIdentity(b *testing.B) {
	// Shaped like (*CachingIdentityAllocator).GetIdentities walking the
	// global identity cache: one model per cached identity, built from the
	// GlobalIdentity's LabelArray.
	arrays := make([]labels.LabelArray, 256)
	for i := range arrays {
		arrays[i] = labels.ParseLabelArray(
			fmt.Sprintf("k8s:app=svc-%03d", i),
			"k8s:io.kubernetes.pod.namespace=default",
			"any:env=prod",
		)
	}

	b.ReportAllocs()
	for b.Loop() {
		out := make([]*models.Identity, 0, len(arrays))
		for i, la := range arrays {
			out = append(out, CreateModelFromLabelArray(identity.NumericIdentity(i), la))
		}
		sinkIdentityModels = out
	}
}
