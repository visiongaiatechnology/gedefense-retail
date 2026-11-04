package vendorcatalog

import (
	"errors"
	"fmt"
	"strings"
)

// Validation vocabularies. Unknown values make the affected document unusable
// (fail-safe): the daemon keeps running, but without the vendor knowledge.
var (
	confidenceValues   = map[string]bool{"high": true, "medium": true, "low": true}
	verificationValues = map[string]bool{
		"fulltext_fetched": true, "secondary_reported": true, "search_result_only": true,
	}
	familyCategories = map[string]bool{
		"store_supervisor": true, "controller_platform": true,
		"rack_controller": true, "cloud_monitoring": true,
	}
	lifecycleValues   = map[string]bool{"current": true, "unknown": true, "legacy_but_supported": true}
	scopeValues       = map[string]bool{"device_family": true, "protocol_generic": true}
	enforcementValues = map[string]bool{
		"gate": true, "manufacturer_process": true, "operator": true, "operator_physical": true,
	}
	transportValues = map[string]bool{"tcp": true, "udp": true, "usb": true, "local": true, "serial": true}
	decisionValues  = map[string]bool{
		"allow": true, "allow_only_via_gate_login": true, "allow_read_normalized": true,
		"deny": true, "deny_always": true, "deny_by_default": true, "not_gate_scope": true,
	}
	operationKindValues = map[string]bool{
		"read": true, "write": true, "write_config": true, "control": true,
		"auth": true, "firmware_update": true,
	}
	criticalityValues = map[string]bool{"critical": true, "high": true, "medium": true, "low": true}
)

// validateVendorsFile checks the vendors.json contract. IDs must be unique,
// families must reference a known vendor, categories/lifecycles/protocols must be
// part of the documented vocabulary and required fields must not be empty.
func validateVendorsFile(vf *vendorsFile) error {
	var issues []string
	if len(vf.Vendors) > MaxVendors {
		issues = append(issues, fmt.Sprintf("%d vendors exceed the limit of %d", len(vf.Vendors), MaxVendors))
	}
	if len(vf.DeviceFamilies) > MaxFamilies {
		issues = append(issues, fmt.Sprintf("%d device families exceed the limit of %d", len(vf.DeviceFamilies), MaxFamilies))
	}
	if len(vf.Protocols) > MaxProtocols {
		issues = append(issues, fmt.Sprintf("%d protocols exceed the limit of %d", len(vf.Protocols), MaxProtocols))
	}

	vendorIDs := make(map[string]bool, len(vf.Vendors))
	for i, vendor := range vf.Vendors {
		if strings.TrimSpace(vendor.ID) == "" || strings.TrimSpace(vendor.Name) == "" {
			issues = append(issues, fmt.Sprintf("vendors[%d]: id and name are required", i))
			continue
		}
		if vendorIDs[vendor.ID] {
			issues = append(issues, "duplicate vendor id "+vendor.ID)
		}
		vendorIDs[vendor.ID] = true
		issues = append(issues, checkEvidence(vendor.Confidence, vendor.Verification, "vendors["+vendor.ID+"]")...)
	}

	protocolIDs := make(map[string]bool, len(vf.Protocols))
	for i, protocol := range vf.Protocols {
		if strings.TrimSpace(protocol.ID) == "" || strings.TrimSpace(protocol.Name) == "" {
			issues = append(issues, fmt.Sprintf("protocols[%d]: id and name are required", i))
			continue
		}
		if protocolIDs[protocol.ID] {
			issues = append(issues, "duplicate protocol id "+protocol.ID)
		}
		protocolIDs[protocol.ID] = true
	}

	familyIDs := make(map[string]bool, len(vf.DeviceFamilies))
	for i, family := range vf.DeviceFamilies {
		label := fmt.Sprintf("device_families[%s]", family.ID)
		if strings.TrimSpace(family.ID) == "" {
			issues = append(issues, fmt.Sprintf("device_families[%d]: id is required", i))
			continue
		}
		if familyIDs[family.ID] {
			issues = append(issues, "duplicate device family id "+family.ID)
		}
		familyIDs[family.ID] = true
		if strings.TrimSpace(family.VendorID) == "" || !vendorIDs[family.VendorID] {
			issues = append(issues, label+": vendor_id must reference a known vendor")
		}
		if strings.TrimSpace(family.Name) == "" {
			issues = append(issues, label+": name is required")
		}
		if !familyCategories[family.Category] {
			issues = append(issues, label+": unknown category "+family.Category)
		}
		if !validLifecycle(family.Lifecycle) {
			issues = append(issues, label+": unknown lifecycle "+family.Lifecycle)
		}
		for _, protocol := range family.Protocols {
			if protocol != "" && !protocolIDs[protocol] {
				issues = append(issues, label+": protocol "+protocol+" is not part of the protocol vocabulary")
			}
		}
		issues = append(issues, checkEvidence(family.Confidence, family.Verification, label)...)
	}
	if len(issues) > 0 {
		return errors.New(strings.Join(issues, "; "))
	}
	return nil
}

// validateWriteSurfaceFile checks write-surface.json and its references into the
// vendor document.
func validateWriteSurfaceFile(wf *writeSurfaceFile, vf *vendorsFile) error {
	var issues []string
	if len(wf.WriteSurfaces) > MaxSurfaces {
		issues = append(issues, fmt.Sprintf("%d write surfaces exceed the limit of %d", len(wf.WriteSurfaces), MaxSurfaces))
	}
	if len(wf.ChangeClasses) > MaxChangeClasses {
		issues = append(issues, fmt.Sprintf("%d change classes exceed the limit of %d", len(wf.ChangeClasses), MaxChangeClasses))
	}

	familyIDs := make(map[string]bool, len(vf.DeviceFamilies))
	for _, family := range vf.DeviceFamilies {
		familyIDs[family.ID] = true
	}

	changeClassIDs := make(map[string]bool, len(wf.ChangeClasses))
	for i, class := range wf.ChangeClasses {
		if strings.TrimSpace(class.ID) == "" || strings.TrimSpace(class.Name) == "" {
			issues = append(issues, fmt.Sprintf("change_classes[%d]: id and name are required", i))
			continue
		}
		if changeClassIDs[class.ID] {
			issues = append(issues, "duplicate change class id "+class.ID)
		}
		changeClassIDs[class.ID] = true
		if class.Criticality != "" && !criticalityValues[class.Criticality] {
			issues = append(issues, "change_classes["+class.ID+"]: unknown criticality "+class.Criticality)
		}
		issues = append(issues, checkEvidence(class.Evidence.Confidence, class.Evidence.Verification, "change_classes["+class.ID+"]")...)
	}

	surfaceIDs := make(map[string]bool, len(wf.WriteSurfaces))
	for i, surface := range wf.WriteSurfaces {
		label := "write_surfaces[" + surface.ID + "]"
		if strings.TrimSpace(surface.ID) == "" {
			issues = append(issues, fmt.Sprintf("write_surfaces[%d]: id is required", i))
			continue
		}
		if surfaceIDs[surface.ID] {
			issues = append(issues, "duplicate write surface id "+surface.ID)
		}
		surfaceIDs[surface.ID] = true
		if !scopeValues[surface.Scope] {
			issues = append(issues, label+": unknown scope "+surface.Scope)
		}
		if strings.TrimSpace(surface.Protocol) == "" {
			issues = append(issues, label+": protocol is required")
		}
		if surface.Enforcement != "" && !enforcementValues[surface.Enforcement] {
			issues = append(issues, label+": unknown enforcement "+surface.Enforcement)
		}
		if surface.Transport != "" && !transportValues[surface.Transport] {
			issues = append(issues, label+": unknown transport "+surface.Transport)
		}
		if len(surface.Operations) > MaxOperations {
			issues = append(issues, label+": too many operations")
		}
		for j, operation := range surface.Operations {
			opLabel := fmt.Sprintf("%s.operations[%d]", label, j)
			if operation.Kind != "" && !operationKindValues[operation.Kind] {
				issues = append(issues, opLabel+": unknown kind "+operation.Kind)
			}
			if !decisionValues[operation.Decision] {
				issues = append(issues, opLabel+": unknown decision "+operation.Decision)
			}
			if operation.ChangeClass != "" && !changeClassIDs[operation.ChangeClass] {
				issues = append(issues, opLabel+": unknown change class "+operation.ChangeClass)
			}
		}
		if strings.TrimSpace(surface.Evidence.Confidence) == "" {
			issues = append(issues, label+": evidence.confidence is required")
		}
		issues = append(issues, checkEvidence(surface.Evidence.Confidence, surface.Evidence.Verification, label)...)

		if surface.Scope == "device_family" {
			if strings.TrimSpace(surface.DeviceFamilyID) == "" || !familyIDs[surface.DeviceFamilyID] {
				issues = append(issues, label+": device_family_id must reference a known device family")
			}
		} else if surface.Scope == "protocol_generic" && surface.DeviceFamilyID != "" {
			issues = append(issues, label+": protocol_generic surfaces must not set device_family_id")
		}
		for _, familyID := range surface.AdditionalFamilyIDs {
			if !familyIDs[familyID] {
				issues = append(issues, label+": additional_family_ids references unknown family "+familyID)
			}
		}
		for _, classID := range surface.CriticalChangeClasses {
			if !changeClassIDs[classID] {
				issues = append(issues, label+": unknown critical change class "+classID)
			}
		}
	}
	if len(issues) > 0 {
		return errors.New(strings.Join(issues, "; "))
	}
	return nil
}

// validateRegulatoryFile checks the regulatory-context.json contract.
func validateRegulatoryFile(rf *regulatoryFile) error {
	var issues []string
	if len(rf.Frameworks) > MaxFrameworks {
		issues = append(issues, fmt.Sprintf("%d frameworks exceed the limit of %d", len(rf.Frameworks), MaxFrameworks))
	}
	frameworkIDs := make(map[string]bool, len(rf.Frameworks))
	for i, framework := range rf.Frameworks {
		if strings.TrimSpace(framework.ID) == "" || strings.TrimSpace(framework.Name) == "" {
			issues = append(issues, fmt.Sprintf("frameworks[%d]: id and name are required", i))
			continue
		}
		if frameworkIDs[framework.ID] {
			issues = append(issues, "duplicate framework id "+framework.ID)
		}
		frameworkIDs[framework.ID] = true
		issues = append(issues, checkEvidence(framework.Confidence, framework.Verification, "frameworks["+framework.ID+"]")...)
	}
	if len(issues) > 0 {
		return errors.New(strings.Join(issues, "; "))
	}
	return nil
}

// checkEvidence validates the two evidence enums when they are present.
func checkEvidence(confidence, verification, label string) []string {
	var issues []string
	if confidence != "" && !confidenceValues[confidence] {
		issues = append(issues, label+": unknown confidence "+confidence)
	}
	if verification != "" && !verificationValues[verification] {
		issues = append(issues, label+": unknown verification "+verification)
	}
	return issues
}

// validLifecycle accepts the documented vocabulary plus the eol_<date> family.
func validLifecycle(raw string) bool {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return false
	}
	if lifecycleValues[value] {
		return true
	}
	return strings.HasPrefix(value, "eol_")
}
