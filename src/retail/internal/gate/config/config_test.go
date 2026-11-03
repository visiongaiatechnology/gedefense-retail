package config

import (
	"strings"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/identity"
)

func testUser(t *testing.T, id string, kind domain.GateUserKind, roles []domain.GateRole, totp bool) domain.GateUser {
	t.Helper()
	hash, err := identity.HashPasswordWithIterations("a-strong-password", identity.MinIterations)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	user := domain.GateUser{UserID: domain.GateUserID(id), Name: id, Kind: kind, Roles: roles,
		PasswordHash: hash, Status: domain.GateUserActive}
	if totp {
		secret, serr := identity.NewTOTPSecret()
		if serr != nil {
			t.Fatalf("secret: %v", serr)
		}
		user.TOTPSecret = secret
		user.TOTPEnabled = true
	}
	return user
}

func baseConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		Listen:  Listen{API: "127.0.0.1:8540"},
		DataDir: "./var/lib/gedefense-gate", SiteID: "filiale-001", GatewayAssetID: "asset-gw",
		PolicyFile: "gate-policy.json",
		Timeouts:   Timeouts{SessionTTLS: 900, TokenTTLS: 300, ApprovalTTLS: 86400, PlanTTLS: 604800, WriteSessionMaxUses: 1},
		Targets: []Target{{
			TargetID: "t1", AssetID: "a1", Protocol: "modbus_tcp", Listen: "127.0.0.1:1502",
			Upstream: "127.0.0.1:502", UnitID: 1, TimeoutS: 5,
			ReadRegisters: &RegisterSpec{FC: 3, Start: 1, Count: 64},
		}},
		SourceCIDRs: []string{"10.10.40.0/24"},
		Users:       []domain.GateUser{testUser(t, "master-1", domain.GateUserAdmin, []domain.GateRole{domain.GateRoleMasterAdmin}, true)},
	}
}

func TestValidateBaseConfig(t *testing.T) {
	config := baseConfig(t).WithDefaults()
	if err := config.Validate(); err != nil {
		t.Fatalf("valid base config rejected: %v", err)
	}
	broken := config
	broken.Targets = append(broken.Targets, broken.Targets[0])
	if err := broken.Validate(); err == nil {
		t.Fatal("duplicate target accepted")
	}
	noMaster := baseConfig(t)
	noMaster.Users = []domain.GateUser{testUser(t, "approver-1", domain.GateUserOperator, []domain.GateRole{domain.GateRoleApprover}, true)}
	if err := noMaster.WithDefaults().Validate(); err == nil {
		t.Fatal("config without master_admin accepted")
	}
	noTOTP := baseConfig(t)
	noTOTP.Users = append(noTOTP.Users, testUser(t, "approver-2", domain.GateUserOperator, []domain.GateRole{domain.GateRoleApprover}, false))
	if err := noTOTP.WithDefaults().Validate(); err == nil {
		t.Fatal("approver without TOTP accepted")
	}
	noCIDR := baseConfig(t)
	noCIDR.SourceCIDRs = nil
	if err := noCIDR.WithDefaults().Validate(); err == nil {
		t.Fatal("empty source_cidrs accepted")
	}
}

func TestStrictJSON(t *testing.T) {
	body := `{"listen":{"api":"127.0.0.1:8540"},"data_dir":"./var/x","site_id":"filiale-001",` +
		`"gateway_asset_id":"asset-gw","policy_file":"gate-policy.json","targets":[],"source_cidrs":["10.0.0.0/8"],` +
		`"users":[{"user_id":"master-1","name":"m","kind":"admin","roles":["master_admin"],` +
		`"password_hash":"` + strings.Repeat("a", 64) + `","status":"active"}],"unknown":true}`
	if _, err := Parse(strings.NewReader(body)); err == nil {
		t.Fatal("unknown configuration field accepted")
	}
}

func TestPolicyValidation(t *testing.T) {
	policy := Policy{
		PolicyID: "gate-policy-test", Version: 1, UpdatedAt: time.Date(2026, 11, 3, 20, 0, 0, 0, time.UTC), UpdatedBy: "master_admin",
		DefaultDeny:          true,
		ModbusWriteAllowlist: []ModbusWriteAllow{{TargetID: "t1", FC: 6, Register: 40001}},
		Token:                TokenPolicy{MaxUses: 1, BindSourceIP: true},
	}
	if err := policy.Validate(); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	if !policy.ModbusOperationAllowed("t1", 6, 40001) || policy.ModbusOperationAllowed("t1", 5, 40001) {
		t.Fatal("modbus allowlist helper is wrong")
	}
	failOpen := policy
	failOpen.DefaultDeny = false
	if err := failOpen.Validate(); err == nil {
		t.Fatal("policy without default_deny accepted")
	}
	badFC := policy
	badFC.ModbusWriteAllowlist = []ModbusWriteAllow{{TargetID: "t1", FC: 3, Register: 1}}
	if err := badFC.Validate(); err == nil {
		t.Fatal("read function code in write allowlist accepted")
	}
}
