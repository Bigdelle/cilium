// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package model

import (
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
)

func NewIdentityFromModel(base *models.Identity) *identity.Identity {
	if base == nil {
		return nil
	}

	id := &identity.Identity{
		ID:     identity.NumericIdentity(base.ID),
		Labels: make(labels.Labels, len(base.Labels)),
	}
	for _, v := range base.Labels {
		lbl := labels.ParseLabel(v)
		id.Labels[lbl.Key] = lbl
	}
	id.Sanitize()

	return id
}

func CreateModel(id *identity.Identity) *models.Identity {
	if id == nil {
		return nil
	}

	return CreateModelFromLabelArray(id.ID, id.LabelArray)
}

// CreateModelFromLabelArray builds the API model for an identity directly from
// its LabelArray.
//
// CreateModel only ever reads id.ID and id.LabelArray, so callers that already
// hold those two do not need an identity.Identity: building one via
// NewIdentityFromLabelArray would allocate a labels.Labels map and fill it with
// one entry per label purely to be discarded again.
func CreateModelFromLabelArray(id identity.NumericIdentity, lblArray labels.LabelArray) *models.Identity {
	ret := &models.Identity{
		ID:     int64(id),
		Labels: make([]string, 0, len(lblArray)),
	}

	for _, v := range lblArray {
		ret.Labels = append(ret.Labels, v.String())
	}
	return ret
}
