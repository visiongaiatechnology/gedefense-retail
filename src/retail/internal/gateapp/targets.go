package gateapp

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	gateconfig "github.com/visiongaiatechnology/gedefense/retail/internal/gate/config"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/modbusproxy"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/targets"
)

// randomHex returns n random bytes as lowercase hex.
func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failure is process-fatal; the gate must not mint weak tokens.
		panic(fmt.Sprintf("gateapp: crypto/rand unavailable: %v", err))
	}
	return hex.EncodeToString(buf)
}

// specForTarget maps the gate configuration onto a data-plane target spec.
// Security-relevant options that are not yet exposed in the config schema are
// pinned to safe alpha defaults (no silent secrets, no implicit write paths).
func specForTarget(t gateconfig.Target) (targets.Spec, error) {
	if t.TargetID == "" || t.AssetID == "" || t.Protocol == "" || t.Listen == "" || t.Upstream == "" {
		return targets.Spec{}, fmt.Errorf("target_id, asset_id, protocol, listen and upstream are required")
	}
	spec := targets.Spec{
		TargetID: t.TargetID,
		AssetID:  t.AssetID,
		Protocol: t.Protocol,
		Listen:   t.Listen,
		Upstream: t.Upstream,
		TimeoutS: t.TimeoutS,
	}
	if spec.TimeoutS <= 0 {
		spec.TimeoutS = 5
	}
	switch t.Protocol {
	case "modbus_tcp":
		unit := t.UnitID
		if unit <= 0 || unit > 255 {
			unit = 1
		}
		spec.UnitID = uint8(unit)
		spec.AllowedUnitIDs = []uint8{uint8(unit)}
		if t.ReadRegisters != nil {
			spec.ReadRegisters = &modbusproxy.RegisterRange{
				FC:    uint8(t.ReadRegisters.FC),
				Start: uint16(t.ReadRegisters.Start),
				Count: uint16(t.ReadRegisters.Count),
			}
		}
		if t.ReadCoils != nil {
			spec.ReadCoils = &modbusproxy.RegisterRange{
				FC:    uint8(t.ReadCoils.FC),
				Start: uint16(t.ReadCoils.Start),
				Count: uint16(t.ReadCoils.Count),
			}
		}
	case "http", "https":
		spec.Protocol = "http"
		spec.URLAllowlist = t.URLAllowlist
		spec.CAFile = t.CAFile
		// Alpha defaults: certificate pinning and CGI write allowlists are not
		// part of the config schema yet. A missing pin is documented, not
		// silently treated as verified identity.
		spec.RequireCertPin = false
		spec.AllowCGIWrites = false
	default:
		return targets.Spec{}, fmt.Errorf("unsupported protocol %q", t.Protocol)
	}
	return spec, nil
}

// parseSourceCIDRs converts configured source ranges to netip prefixes.
func parseSourceCIDRs(cidrs []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, raw := range cidrs {
		if p, err := netip.ParsePrefix(raw); err == nil {
			out = append(out, p.Masked())
			continue
		}
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid source cidr %q", raw)
		}
		bits := 128
		if addr.Is4() {
			bits = 32
		}
		out = append(out, netip.PrefixFrom(addr, bits))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one source_cidr is required (fail-closed)")
	}
	return out, nil
}

// targetByID finds a configured target by identifier.
func targetByID(targetsCfg []gateconfig.Target, id domain.TargetID) (gateconfig.Target, bool) {
	for _, t := range targetsCfg {
		if t.TargetID == id {
			return t, true
		}
	}
	return gateconfig.Target{}, false
}
