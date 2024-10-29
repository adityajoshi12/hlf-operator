/*
 * Copyright Kungfusoftware.es. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1alpha1

// FabricIdentityAttributeRequestApplyConfiguration represents a declarative configuration of the FabricIdentityAttributeRequest type for use
// with apply.
type FabricIdentityAttributeRequestApplyConfiguration struct {
	Name     *string `json:"name,omitempty"`
	Optional *bool   `json:"optional,omitempty"`
}

// FabricIdentityAttributeRequestApplyConfiguration constructs a declarative configuration of the FabricIdentityAttributeRequest type for use with
// apply.
func FabricIdentityAttributeRequest() *FabricIdentityAttributeRequestApplyConfiguration {
	return &FabricIdentityAttributeRequestApplyConfiguration{}
}

// WithName sets the Name field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Name field is set to the value of the last call.
func (b *FabricIdentityAttributeRequestApplyConfiguration) WithName(value string) *FabricIdentityAttributeRequestApplyConfiguration {
	b.Name = &value
	return b
}

// WithOptional sets the Optional field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Optional field is set to the value of the last call.
func (b *FabricIdentityAttributeRequestApplyConfiguration) WithOptional(value bool) *FabricIdentityAttributeRequestApplyConfiguration {
	b.Optional = &value
	return b
}