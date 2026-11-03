package detect

// newRuleSet assembles the shipped rule instances. The order is irrelevant for
// correctness (rules are independent and the result is sorted), but it is kept
// stable so tests and operators see the same evaluation order.
func newRuleSet() ([]Rule, []TickRule) {
	gap := newGapRule()
	lifecycle := newAssetLifecycleRule()

	eventRules := []Rule{
		newUnknownPeerRule(),
		newWriteAttemptRule(),
		newOffWindowAccessRule(),
		newUntrustedVendorRule(),
		newManagementUIAccessRule(),
		newThermalLimitRule(),
		newThermalRateRule(),
		newSetpointDeviationRule(),
		newSensorDivergenceRule(),
		newFrozenValueRule(),
		gap,
		newClockSkewRule(),
		newIntegrityChangeRule(),
		newNewAssetRule(),
	}
	tickRules := []TickRule{
		gap,
		lifecycle,
	}
	all := make([]Rule, 0, len(eventRules)+1)
	all = append(all, eventRules...)
	all = append(all, lifecycle)
	return all, tickRules
}
