// Register specification parsing and the read-only enforcement gate.
package modbus

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/guard"
)

// ErrInvalidRegisterSpec is returned for malformed register specifications.
var ErrInvalidRegisterSpec = errors.New("modbus: invalid register spec")

// RegisterSpec is one operator-approved read-only register mapping.
type RegisterSpec struct {
	Function uint8 // 3 (holding) or 4 (input); never a write function
	Address  uint16
	SensorID domain.SensorID
	AssetID  domain.AssetID
	Metric   string
	Unit     domain.Unit
	Scale    float64 // raw*Scale + Offset; default 1
	Offset   float64
}

// RegisterName renders the conventional Modbus register label, e.g.
// holding:40001 or input:30001. It is metadata only, never a write target.
func (s RegisterSpec) RegisterName() string {
	switch s.Function {
	case fcReadHolding:
		return fmt.Sprintf("holding:%d", 40001+int(s.Address))
	case fcReadInput:
		return fmt.Sprintf("input:%d", 30001+int(s.Address))
	default:
		return fmt.Sprintf("fc%d:%d", s.Function, s.Address)
	}
}

// Direction labels for a decoded tap frame.
type Direction uint8

const (
	DirectionUnknown Direction = iota
	DirectionToServer
	DirectionToClient
)

// String returns a stable label used only for diagnostics.
func (d Direction) String() string {
	switch d {
	case DirectionToServer:
		return "to_server"
	case DirectionToClient:
		return "to_client"
	default:
		return "unknown"
	}
}

// registerFunction is the subset of Modbus function codes the product may use
// for reading. Everything else is rejected by the gate below.
func isReadFunction(fc uint8) bool { return fc == fcReadHolding || fc == fcReadInput }

// isObservedWriteFunction reports whether fc is a write function that a tap may
// observe. The adapter never encodes these codes.
func isObservedWriteFunction(fc uint8) bool {
	switch fc {
	case fcWriteSingleCoil, fcWriteSingleRegister, fcWriteMultipleCoils, fcWriteMultipleRegisters:
		return true
	}
	return false
}

// writeFunctionName maps an observed write function code to the stable event
// label used in domain.WriteAttempt.Function.
func writeFunctionName(fc uint8) string {
	switch fc {
	case fcWriteSingleCoil:
		return "fc5_write_single_coil"
	case fcWriteSingleRegister:
		return "fc6_write_single_register"
	case fcWriteMultipleCoils:
		return "fc15_write_multiple_coils"
	case fcWriteMultipleRegisters:
		return "fc16_write_multiple_registers"
	default:
		return fmt.Sprintf("fc%d_write", fc)
	}
}

// enforceReadOnly is the single gate for register specifications. It funnels
// every write function code through guard.Capability.DenyWrite, so a write
// specification can never become reachable by configuration.
func enforceReadOnly(cap guard.Capability, fc uint8) error {
	switch fc {
	case fcReadHolding, fcReadInput:
		return nil
	case fcWriteSingleCoil:
		return cap.DenyWrite("modbus", writeFunctionName(fc))
	case fcWriteSingleRegister:
		return cap.DenyWrite("modbus", writeFunctionName(fc))
	case fcWriteMultipleCoils:
		return cap.DenyWrite("modbus", writeFunctionName(fc))
	case fcWriteMultipleRegisters:
		return cap.DenyWrite("modbus", writeFunctionName(fc))
	default:
		return fmt.Errorf("%w: unsupported function code %d (only FC3/FC4 are allowed)", ErrInvalidRegisterSpec, fc)
	}
}

// ParseRegisterSpec parses the "registers" option:
//
//	fc:addr:sensor_id:metric:unit[:scale[:offset]];[next;...]
//
// Only FC3/FC4 are accepted; FC5/6/15/16 return an error wrapping
// guard.ErrWriteDenied. Empty input yields no registers (valid in tap mode).
func ParseRegisterSpec(value string) ([]RegisterSpec, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	entries := strings.FieldsFunc(value, func(r rune) bool { return r == ';' || r == '\n' })
	out := make([]RegisterSpec, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	capability := guard.ReadOnly()
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		spec, err := parseRegisterEntry(entry, capability)
		if err != nil {
			return nil, err
		}
		key := fmt.Sprintf("%d/%d", spec.Function, spec.Address)
		if _, dup := seen[key]; dup {
			return nil, fmt.Errorf("%w: duplicate register %s", ErrInvalidRegisterSpec, spec.RegisterName())
		}
		seen[key] = struct{}{}
		out = append(out, spec)
	}
	return out, nil
}

func parseRegisterEntry(entry string, capability guard.Capability) (RegisterSpec, error) {
	parts := strings.Split(entry, ":")
	if len(parts) < 5 {
		return RegisterSpec{}, fmt.Errorf("%w: %q needs fc:addr:sensor_id:metric:unit", ErrInvalidRegisterSpec, entry)
	}
	if len(parts) > 7 {
		return RegisterSpec{}, fmt.Errorf("%w: %q has too many fields", ErrInvalidRegisterSpec, entry)
	}
	fc, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 8)
	if err != nil {
		return RegisterSpec{}, fmt.Errorf("%w: %q: function code is not numeric", ErrInvalidRegisterSpec, entry)
	}
	if err := enforceReadOnly(capability, uint8(fc)); err != nil {
		return RegisterSpec{}, err
	}
	addr, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 16)
	if err != nil {
		return RegisterSpec{}, fmt.Errorf("%w: %q: address is not a 16-bit number", ErrInvalidRegisterSpec, entry)
	}
	sensor := domain.SensorID(strings.TrimSpace(parts[2]))
	if err := sensor.Validate(); err != nil {
		return RegisterSpec{}, fmt.Errorf("%w: %q: sensor: %v", ErrInvalidRegisterSpec, entry, err)
	}
	metric := strings.TrimSpace(parts[3])
	if metric == "" || len(metric) > 64 {
		return RegisterSpec{}, fmt.Errorf("%w: %q: metric is required (max 64)", ErrInvalidRegisterSpec, entry)
	}
	unit := domain.Unit(strings.TrimSpace(parts[4]))
	if !unit.Valid() {
		return RegisterSpec{}, fmt.Errorf("%w: %q: invalid unit %q", ErrInvalidRegisterSpec, entry, parts[4])
	}
	spec := RegisterSpec{
		Function: uint8(fc),
		Address:  uint16(addr),
		SensorID: sensor,
		Metric:   metric,
		Unit:     unit,
		Scale:    1,
	}
	if len(parts) >= 6 {
		scale, err := strconv.ParseFloat(strings.TrimSpace(parts[5]), 64)
		if err != nil || math.IsNaN(scale) || math.IsInf(scale, 0) || scale == 0 {
			return RegisterSpec{}, fmt.Errorf("%w: %q: scale must be a finite non-zero number", ErrInvalidRegisterSpec, entry)
		}
		spec.Scale = scale
	}
	if len(parts) == 7 {
		offset, err := strconv.ParseFloat(strings.TrimSpace(parts[6]), 64)
		if err != nil || math.IsNaN(offset) || math.IsInf(offset, 0) {
			return RegisterSpec{}, fmt.Errorf("%w: %q: offset must be a finite number", ErrInvalidRegisterSpec, entry)
		}
		spec.Offset = offset
	}
	return spec, nil
}

// indexRegisters groups the specs by function code and address for O(1)
// response decoding.
func indexRegisters(specs []RegisterSpec) map[uint8]map[uint16]RegisterSpec {
	out := make(map[uint8]map[uint16]RegisterSpec, 2)
	for _, spec := range specs {
		byAddr, ok := out[spec.Function]
		if !ok {
			byAddr = make(map[uint16]RegisterSpec)
			out[spec.Function] = byAddr
		}
		byAddr[spec.Address] = spec
	}
	return out
}

// scaleRaw converts a signed 16-bit register value into the engineering value.
// Modbus registers are unsigned on the wire; cold-chain temperatures are
// usually transmitted as signed int16 (for example -18.0 °C as 0xFFEE), so the
// adapter always interprets the raw value as int16.
func scaleRaw(raw uint16, spec RegisterSpec) float64 {
	return float64(int16(raw))*spec.Scale + spec.Offset
}
