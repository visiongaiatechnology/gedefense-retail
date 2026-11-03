// Read-only Modbus/TCP slave simulator.
package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/guard"
)

// modbusFunction handlers used by the simulator.
const (
	fcReadHolding            uint8 = 3
	fcReadInput              uint8 = 4
	fcWriteSingleCoil        uint8 = 5
	fcWriteSingleRegister    uint8 = 6
	fcWriteMultipleCoils     uint8 = 15
	fcWriteMultipleRegisters uint8 = 16
)

// registerMap is the simulated controller state. It is never mutated by a
// write request: the simulator answers exception 0x01 like a read-only device.
type registerMap struct {
	holding []uint16
	input   []uint16
}

// scenarioRegisters builds the deterministic register map for a scenario.
func scenarioRegisters(scenario string) registerMap {
	holding := make([]uint16, 16)
	input := make([]uint16, 16)
	switch scenario {
	case "attack":
		// Manipulated setpoint and a heating phase: classic cold-chain attack
		// evidence, still only simulated data.
		holding[0] = uint16(int16(12 * 10)) // air temperature 12.0 C
		holding[1] = uint16(int16(12 * 10))
		holding[2] = 0 // cooling
		holding[3] = 0 // door closed
		holding[4] = 1 // alarm bit set
		input[0] = uint16(int16(12 * 10))
		input[1] = uint16(int16(11 * 10))
		input[2] = uint16(int16(13 * 10))
	default:
		holding[0] = uint16(int16(42)) // 4.2 C
		holding[1] = uint16(int16(40)) // setpoint 4.0 C
		holding[2] = 0                 // cooling
		holding[3] = 0                 // door closed
		holding[4] = 0                 // no alarm
		input[0] = uint16(int16(42))
		input[1] = uint16(int16(39))
		input[2] = uint16(int16(44))
	}
	return registerMap{holding: holding, input: input}
}

// runModbusServer starts the simulator and blocks until interrupt/cancel.
func runModbusServer(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("modbus-server", stderr)
	listen := fs.String("listen", "127.0.0.1:15020", "listen address")
	scenario := fs.String("scenario", "normal", "normal|attack")
	unitID := fs.Int("unit", 1, "Modbus unit id")
	readOnly := fs.Bool("read-only", true, "reject write function codes (always true)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*readOnly {
		return fmt.Errorf("modbus-server: read-only is a product invariant and cannot be disabled")
	}
	if *unitID < 0 || *unitID > 255 {
		return fmt.Errorf("modbus-server: unit must be 0..255")
	}
	if *scenario != "normal" && *scenario != "attack" {
		return fmt.Errorf("modbus-server: unknown scenario %q (normal|attack)", *scenario)
	}
	ctx, cancel := signalContext()
	defer cancel()
	return serveModbusServer(ctx, *listen, *scenario, *unitID, stdout, stderr)
}

// serveModbusServer runs the TCP slave until ctx is cancelled. It is separated
// from flag parsing so tests can drive it with a cancellable context.
func serveModbusServer(ctx context.Context, listen, scenario string, unitID int, stdout, stderr io.Writer) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", listen)
	if err != nil {
		return fmt.Errorf("listen %q: %w", listen, err)
	}
	defer func() { _ = ln.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()

	regs := scenarioRegisters(scenario)
	fmt.Fprintf(stdout, "MODBUS_SERVER listening=%s scenario=%s unit=%d read_only=true\n", listen, scenario, unitID)

	var wg sync.WaitGroup
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			fmt.Fprintf(stderr, "MODBUS_SERVER accept_error=%v\n", err)
			continue
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer func() { _ = c.Close() }()
			serveModbusSlave(ctx, c, regs, uint8(unitID), stdout)
		}(conn)
	}
	wg.Wait()
	return nil
}

// serveModbusSlave answers FC3/FC4 reads and rejects every write function code
// with exception 0x01 without touching the register map.
func serveModbusSlave(ctx context.Context, conn net.Conn, regs registerMap, unitID uint8, stdout io.Writer) {
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer stop()
	header := make([]byte, 6)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return
		}
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}
		length := int(binary.BigEndian.Uint16(header[4:6]))
		if length < 2 || length > 260 {
			return
		}
		body := make([]byte, length)
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}
		unit := body[0]
		pdu := body[1:]
		if len(pdu) == 0 {
			return
		}
		txID := binary.BigEndian.Uint16(header[0:2])
		reply := handleModbusPDU(txID, unit, pdu, regs, unitID, stdout)
		if len(reply) == 0 {
			continue
		}
		if _, err := conn.Write(reply); err != nil {
			return
		}
	}
}

// handleModbusPDU returns the response frame (or nil when no response is
// defined for the request).
func handleModbusPDU(txID uint16, unit uint8, pdu []byte, regs registerMap, configuredUnit uint8, stdout io.Writer) []byte {
	fc := pdu[0]
	if unit != configuredUnit {
		return modbusException(txID, unit, fc, 0x0b) // gateway target failed
	}
	switch fc {
	case fcReadHolding, fcReadInput:
		if len(pdu) != 5 {
			return modbusException(txID, unit, fc, 0x03)
		}
		address := binary.BigEndian.Uint16(pdu[1:3])
		quantity := binary.BigEndian.Uint16(pdu[3:5])
		if quantity == 0 || quantity > 125 {
			return modbusException(txID, unit, fc, 0x03)
		}
		source := regs.holding
		if fc == fcReadInput {
			source = regs.input
		}
		values := make([]uint16, quantity)
		for i := 0; i < int(quantity); i++ {
			idx := int(address) + i
			if idx >= 0 && idx < len(source) {
				values[i] = source[idx]
			}
		}
		response := make([]byte, 0, 9+2*len(values))
		response = append(response, byte(txID>>8), byte(txID), 0, 0, 0, 0, unit, fc, byte(2*len(values)))
		for _, value := range values {
			response = append(response, byte(value>>8), byte(value))
		}
		binary.BigEndian.PutUint16(response[4:6], uint16(len(response)-6))
		return response
	case fcWriteSingleCoil, fcWriteSingleRegister, fcWriteMultipleCoils, fcWriteMultipleRegisters:
		// Read-only simulator: the write is observed (logged) and rejected; the
		// register map is never mutated. This mirrors the product invariant.
		denied := guard.ReadOnly().DenyWrite("modbus", writeFunctionLabel(fc))
		fmt.Fprintf(stdout, "MODBUS_WRITE_REJECTED fc=%d unit=%d reason=%q (register map unchanged)\n", fc, unit, denied.Error())
		return modbusException(txID, unit, fc, 0x01)
	default:
		return modbusException(txID, unit, fc, 0x01)
	}
}

func writeFunctionLabel(fc uint8) string {
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
		return "write"
	}
}

// modbusException builds an exception response frame.
func modbusException(txID uint16, unit, fc, code uint8) []byte {
	return []byte{byte(txID >> 8), byte(txID), 0, 0, 0, 3, unit, fc | 0x80, code}
}
