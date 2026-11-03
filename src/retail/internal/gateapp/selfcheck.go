package gateapp

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	gateconfig "github.com/visiongaiatechnology/gedefense/retail/internal/gate/config"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/store"
	"github.com/visiongaiatechnology/gedefense/retail/internal/version"
)

// CheckResult is one entry of the `retailgate check` report.
type CheckResult struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// Report is the machine-readable self-check output.
type Report struct {
	OK        bool          `json:"ok"`
	Version   version.Info  `json:"version"`
	Product   string        `json:"product"`
	SiteID    string        `json:"site_id"`
	Checks    []CheckResult `json:"checks"`
	Warnings  []string      `json:"warnings,omitempty"`
	CheckedAt time.Time     `json:"checked_at"`
}

// Check validates the gate configuration, policy and local runtime
// preconditions. It never starts listeners and never writes to the data
// directory beyond opening/verifying existing state.
func Check(cfg gateconfig.Config, configPath string) (Report, error) {
	now := time.Now().UTC()
	rep := Report{
		Version:   version.Current(),
		Product:   "GeDefense Retail Access Gate",
		SiteID:    string(cfg.SiteID),
		CheckedAt: now,
	}

	rep.Checks = append(rep.Checks, checkResult("CFG-01", "Konfiguration valide", cfg.Validate()))

	policyPath := resolvePolicyPath(cfg, configPath)
	policy, perr := gateconfig.LoadPolicy(policyPath)
	rep.Checks = append(rep.Checks, checkResult("POL-01", "Policy lesbar und valide", perr))
	if perr == nil {
		rep.Checks = append(rep.Checks, CheckResult{
			ID: "POL-02", Name: "Default-Deny ist aktiv", OK: policy.DefaultDeny,
			Detail: "default_deny=false ist nicht zulässig",
		})
	}

	master := false
	for _, u := range cfg.Users {
		if u.HasRole(domain.GateRoleMasterAdmin) && u.Status == domain.GateUserActive {
			master = true
			break
		}
	}
	rep.Checks = append(rep.Checks, CheckResult{
		ID: "USR-01", Name: "Aktiver master_admin vorhanden", OK: master,
		Detail: "mindestens ein aktiver master_admin ist erforderlich",
	})

	rep.Checks = append(rep.Checks, checkResult("SRC-01", "source_cidrs konfiguriert (fail-closed)", errIf(len(cfg.SourceCIDRs) == 0, "source_cidrs is empty")))

	for _, t := range cfg.Targets {
		_, err := specForTarget(t)
		rep.Checks = append(rep.Checks, CheckResult{
			ID: "TGT-" + string(t.TargetID), Name: "Target " + string(t.TargetID) + " konfiguriert", OK: err == nil, Detail: errText(err),
		})
		if t.Protocol == "http" || t.Protocol == "https" {
			if t.CAFile == "" {
				rep.Warnings = append(rep.Warnings, "target "+string(t.TargetID)+": kein ca_file und kein Cert-Pinning in der Alpha (TLS-Kette wird gegen System-CAs geprüft)")
			}
		}
	}

	if cfg.Notify.WebhookURL != "" {
		ok := len(cfg.Notify.HMACSecret) >= 16
		rep.Checks = append(rep.Checks, CheckResult{
			ID: "NTF-01", Name: "Webhook HMAC-Secret ausreichend", OK: ok,
			Detail: "hmac_secret muss mindestens 16 Bytes haben",
		})
	}

	st, err := store.Open(store.Options{Dir: cfg.EffectiveDataDir(), Clock: systemClock{}})
	if err != nil {
		rep.Checks = append(rep.Checks, CheckResult{ID: "STO-01", Name: "Gate-Store lesbar", OK: false, Detail: err.Error()})
	} else {
		ok, seq, verr := st.VerifyAudit(context.Background())
		detail := errText(verr)
		if !ok {
			detail = "audit chain broken at seq " + itoa(seq)
		}
		rep.Checks = append(rep.Checks, CheckResult{ID: "STO-01", Name: "Gate-Store lesbar", OK: true})
		rep.Checks = append(rep.Checks, CheckResult{ID: "STO-02", Name: "Audit-Kette valide", OK: ok, Detail: detail})
		if cerr := st.Close(); cerr != nil {
			rep.Warnings = append(rep.Warnings, "store close: "+cerr.Error())
		}
	}

	rep.OK = true
	for _, c := range rep.Checks {
		if !c.OK {
			rep.OK = false
			break
		}
	}
	return rep, nil
}

func checkResult(id, name string, err error) CheckResult {
	return CheckResult{ID: id, Name: name, OK: err == nil, Detail: errText(err)}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func errIf(cond bool, msg string) error {
	if cond {
		return errors.New(msg)
	}
	return nil
}

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

// ensure interface use
var _ fs.FileInfo
var _ = filepath.Separator
var _ = os.ErrNotExist
