// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1alpha1

// TLSApplyConfiguration represents an declarative configuration of the TLS type for use
// with apply.
type TLSApplyConfiguration struct {
	Cahost       *string                                `json:"cahost,omitempty"`
	Caname       *string                                `json:"caname,omitempty"`
	Caport       *int                                   `json:"caport,omitempty"`
	Catls        *CatlsApplyConfiguration               `json:"catls,omitempty"`
	Csr          *CsrApplyConfiguration                 `json:"csr,omitempty"`
	Enrollid     *string                                `json:"enrollid,omitempty"`
	Enrollsecret *string                                `json:"enrollsecret,omitempty"`
	External     *ExternalCertificateApplyConfiguration `json:"external,omitempty"`
}

// TLSApplyConfiguration constructs an declarative configuration of the TLS type for use with
// apply.
func TLS() *TLSApplyConfiguration {
	return &TLSApplyConfiguration{}
}

// WithCahost sets the Cahost field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Cahost field is set to the value of the last call.
func (b *TLSApplyConfiguration) WithCahost(value string) *TLSApplyConfiguration {
	b.Cahost = &value
	return b
}

// WithCaname sets the Caname field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Caname field is set to the value of the last call.
func (b *TLSApplyConfiguration) WithCaname(value string) *TLSApplyConfiguration {
	b.Caname = &value
	return b
}

// WithCaport sets the Caport field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Caport field is set to the value of the last call.
func (b *TLSApplyConfiguration) WithCaport(value int) *TLSApplyConfiguration {
	b.Caport = &value
	return b
}

// WithCatls sets the Catls field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Catls field is set to the value of the last call.
func (b *TLSApplyConfiguration) WithCatls(value *CatlsApplyConfiguration) *TLSApplyConfiguration {
	b.Catls = value
	return b
}

// WithCsr sets the Csr field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Csr field is set to the value of the last call.
func (b *TLSApplyConfiguration) WithCsr(value *CsrApplyConfiguration) *TLSApplyConfiguration {
	b.Csr = value
	return b
}

// WithEnrollid sets the Enrollid field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Enrollid field is set to the value of the last call.
func (b *TLSApplyConfiguration) WithEnrollid(value string) *TLSApplyConfiguration {
	b.Enrollid = &value
	return b
}

// WithEnrollsecret sets the Enrollsecret field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Enrollsecret field is set to the value of the last call.
func (b *TLSApplyConfiguration) WithEnrollsecret(value string) *TLSApplyConfiguration {
	b.Enrollsecret = &value
	return b
}

// WithExternal sets the External field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the External field is set to the value of the last call.
func (b *TLSApplyConfiguration) WithExternal(value *ExternalCertificateApplyConfiguration) *TLSApplyConfiguration {
	b.External = value
	return b
}