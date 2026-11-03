// Package guard holds the non-negotiable safety invariants of GeDefense Retail
// in code. It is intentionally tiny: every adapter, detection rule and API
// handler can reference it, and the security test suite asserts that no
// production package contains a write path to an OT device.
//
// The product is passive by design (blueprint §2.2). The MVP must not contain
// ANY code that can mutate a PLC, refrigeration controller or actuator. This
// package makes that rule explicit, testable and impossible to "accidentally"
// bypass through a helper function.
package guard

import (
	"errors"
	"fmt"
)

// ErrWriteDenied is returned by every attempt to use a write capability.
var ErrWriteDenied = errors.New("ot write access denied by product invariant")

// Capability is a sealed, non-forgeable marker. The zero value is useless; the
// only supported capability is ReadOnly.
type Capability struct {
	readOnly bool
}

// ReadOnly returns the single capability that the product supports. Adapters
// that poll devices receive this capability and must pass it to any accessor.
func ReadOnly() Capability { return Capability{readOnly: true} }

// IsReadOnly reports the capability mode.
func (c Capability) IsReadOnly() bool { return c.readOnly }

// DenyWrite is the single funnel for write attempts. It always denies. Callers
// reach it when an operator asks for an unsupported action, or when untrusted
// input tries to smuggle a write request through the API.
func (c Capability) DenyWrite(protocol, operation string) error {
	return fmt.Errorf("%w: protocol=%q operation=%q", ErrWriteDenied, protocol, operation)
}

// ForbidActiveScan is the passive-only counterpart for scanning: the MVP must
// never emit unsolicited probe traffic into a production OT network.
var ErrActiveScanDenied = errors.New("active ot scanning denied by product invariant")

// DenyActiveScan always denies active probing.
func DenyActiveScan(protocol, target string) error {
	return fmt.Errorf("%w: protocol=%q target=%q", ErrActiveScanDenied, protocol, target)
}

// DenyPlantControl denies every attempt to change a plant process value, even
// when it is disguised as a "safety" action.
var ErrPlantControlDenied = errors.New("plant control denied by product invariant")

// DenyPlantControl always denies plant control actions.
func DenyPlantControl(action, asset string) error {
	return fmt.Errorf("%w: action=%q asset=%q", ErrPlantControlDenied, action, asset)
}
