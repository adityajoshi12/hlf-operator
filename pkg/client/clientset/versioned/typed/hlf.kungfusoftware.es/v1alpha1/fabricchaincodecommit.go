/*
 * Copyright Kungfusoftware.es. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"

	v1alpha1 "github.com/kfsoftware/hlf-operator/pkg/apis/hlf.kungfusoftware.es/v1alpha1"
	hlfkungfusoftwareesv1alpha1 "github.com/kfsoftware/hlf-operator/pkg/client/applyconfiguration/hlf.kungfusoftware.es/v1alpha1"
	scheme "github.com/kfsoftware/hlf-operator/pkg/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	gentype "k8s.io/client-go/gentype"
)

// FabricChaincodeCommitsGetter has a method to return a FabricChaincodeCommitInterface.
// A group's client should implement this interface.
type FabricChaincodeCommitsGetter interface {
	FabricChaincodeCommits() FabricChaincodeCommitInterface
}

// FabricChaincodeCommitInterface has methods to work with FabricChaincodeCommit resources.
type FabricChaincodeCommitInterface interface {
	Create(ctx context.Context, fabricChaincodeCommit *v1alpha1.FabricChaincodeCommit, opts v1.CreateOptions) (*v1alpha1.FabricChaincodeCommit, error)
	Update(ctx context.Context, fabricChaincodeCommit *v1alpha1.FabricChaincodeCommit, opts v1.UpdateOptions) (*v1alpha1.FabricChaincodeCommit, error)
	// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
	UpdateStatus(ctx context.Context, fabricChaincodeCommit *v1alpha1.FabricChaincodeCommit, opts v1.UpdateOptions) (*v1alpha1.FabricChaincodeCommit, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.FabricChaincodeCommit, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.FabricChaincodeCommitList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.FabricChaincodeCommit, err error)
	Apply(ctx context.Context, fabricChaincodeCommit *hlfkungfusoftwareesv1alpha1.FabricChaincodeCommitApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.FabricChaincodeCommit, err error)
	// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
	ApplyStatus(ctx context.Context, fabricChaincodeCommit *hlfkungfusoftwareesv1alpha1.FabricChaincodeCommitApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.FabricChaincodeCommit, err error)
	FabricChaincodeCommitExpansion
}

// fabricChaincodeCommits implements FabricChaincodeCommitInterface
type fabricChaincodeCommits struct {
	*gentype.ClientWithListAndApply[*v1alpha1.FabricChaincodeCommit, *v1alpha1.FabricChaincodeCommitList, *hlfkungfusoftwareesv1alpha1.FabricChaincodeCommitApplyConfiguration]
}

// newFabricChaincodeCommits returns a FabricChaincodeCommits
func newFabricChaincodeCommits(c *HlfV1alpha1Client) *fabricChaincodeCommits {
	return &fabricChaincodeCommits{
		gentype.NewClientWithListAndApply[*v1alpha1.FabricChaincodeCommit, *v1alpha1.FabricChaincodeCommitList, *hlfkungfusoftwareesv1alpha1.FabricChaincodeCommitApplyConfiguration](
			"fabricchaincodecommits",
			c.RESTClient(),
			scheme.ParameterCodec,
			"",
			func() *v1alpha1.FabricChaincodeCommit { return &v1alpha1.FabricChaincodeCommit{} },
			func() *v1alpha1.FabricChaincodeCommitList { return &v1alpha1.FabricChaincodeCommitList{} }),
	}
}