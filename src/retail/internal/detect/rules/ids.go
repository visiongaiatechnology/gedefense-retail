package rules

import (
	"strings"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// Rule identifiers of the GeDefense Retail MVP rule pack. The identifiers are
// part of the external contract (alert.rule_id, policy references, UI labels)
// and must not change once shipped: a behaviour change requires a new Version.
const (
	IDUnknownPeer             = domain.RuleID("retail.net.unknown-peer")
	IDWriteAttempt            = domain.RuleID("retail.write-attempt")
	IDAccessOffWindow         = domain.RuleID("retail.access.off-window")
	IDAccessUntrustedVendor   = domain.RuleID("retail.access.untrusted-vendor")
	IDAccessManagementUI      = domain.RuleID("retail.access.management-ui")
	IDThermalLimit            = domain.RuleID("retail.thermal.limit")
	IDThermalRate             = domain.RuleID("retail.thermal.rate")
	IDThermalSetpoint         = domain.RuleID("retail.thermal.setpoint-deviation")
	IDThermalSensorDivergence = domain.RuleID("retail.thermal.sensor-divergence")
	IDDataQualityFrozen       = domain.RuleID("retail.dq.frozen-value")
	IDDataQualityGap          = domain.RuleID("retail.dq.gap")
	IDDataQualityClockSkew    = domain.RuleID("retail.dq.clock-skew")
	IDIntegrityChange         = domain.RuleID("retail.integrity.change")
	IDDeviceNewAsset          = domain.RuleID("retail.device.new-asset")
	IDAssetLifecycleExposed   = domain.RuleID("retail.asset.lifecycle-exposed")
	// IDBypassSuspected is emitted by the retaild bypass adapter (task-44) when a
	// passive write attempt is observed outside the configured Gate sources. It is
	// not part of the passive rule pack catalogue: the signal comes from the gate
	// bypass package, not from EvaluateEvent.
	IDBypassSuspected = domain.RuleID("retail.bypass-suspected")
)

// Version is the rule-pack version stored in every alert. A change to the
// detection logic, thresholds or observable semantics requires a new version so
// operators can explain historical alerts.
const Version = "1"

const (
	dedupSeparator   = "|"
	dedupMaxLen      = 256
	dedupPartMaxLen  = 64
	dedupAllowedChar = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/-"
)

// DedupKey builds the stable deduplication key of an alert. The first part is
// the rule identifier; the following parts are rule-specific dimensions (site,
// source, target, metric, …). Parts are sanitised because they may be derived
// from observed network metadata, and the key is persisted in JSONL files and
// used as an in-memory map key.
func DedupKey(id domain.RuleID, parts ...string) string {
	var b strings.Builder
	b.WriteString(string(id))
	for _, part := range parts {
		p := sanitizePart(part)
		if p == "" {
			continue
		}
		b.WriteString(dedupSeparator)
		b.WriteString(p)
		if b.Len() >= dedupMaxLen {
			break
		}
	}
	key := b.String()
	if len(key) > dedupMaxLen {
		key = key[:dedupMaxLen]
	}
	return key
}

func sanitizePart(part string) string {
	part = strings.TrimSpace(part)
	if part == "" {
		return ""
	}
	if len(part) > dedupPartMaxLen {
		part = part[:dedupPartMaxLen]
	}
	var b strings.Builder
	b.Grow(len(part))
	for i := 0; i < len(part); i++ {
		c := part[i]
		if strings.IndexByte(dedupAllowedChar, c) >= 0 {
			b.WriteByte(c)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}
