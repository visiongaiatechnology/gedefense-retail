package app

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/config"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/vendorcatalog"
	"github.com/visiongaiatechnology/gedefense/retail/internal/version"
	"github.com/visiongaiatechnology/gedefense/retail/internal/webui"
)

// CheckResult is one entry of the `retaild check` report.
type CheckResult struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// Report is the machine-readable self-check output. It performs no network
// operations and never writes production data (it only probes directory
// writability with a temporary file that is removed again).
type Report struct {
	OK        bool          `json:"ok"`
	Version   version.Info  `json:"version"`
	Product   string        `json:"product"`
	SiteID    string        `json:"site_id"`
	Checks    []CheckResult `json:"checks"`
	Warnings  []string      `json:"warnings,omitempty"`
	CheckedAt time.Time     `json:"checked_at"`
}

// shippedAdapters lists the adapter kinds compiled into this binary.
var shippedAdapters = []string{"modbus", "mqtt", "bacnet", "snmp", "pcap", "httpui"}

// Check validates a configuration and the local runtime preconditions.
func Check(cfg config.Config) (Report, error) {
	rep := Report{
		Version:   version.Current(),
		Product:   version.Product,
		SiteID:    string(cfg.Site.SiteID),
		CheckedAt: time.Now().UTC(),
	}
	rep.Warnings = append(rep.Warnings, cfg.Warnings()...)
	rep.Checks = append(rep.Checks, CheckResult{
		ID: "CFG-01", Name: "Konfiguration valide", OK: cfg.Validate() == nil,
		Detail: errText(cfg.Validate()),
	})

	dataDir := cfg.EffectiveDataDir()
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		rep.Checks = append(rep.Checks, CheckResult{ID: "STO-01", Name: "Datenverzeichnis schreibbar", OK: false, Detail: err.Error()})
	} else {
		probe, err := os.CreateTemp(dataDir, ".check-*")
		if err != nil {
			rep.Checks = append(rep.Checks, CheckResult{ID: "STO-01", Name: "Datenverzeichnis schreibbar", OK: false, Detail: err.Error()})
		} else {
			name := probe.Name()
			_, werr := probe.Write([]byte("gedefense-retail-check"))
			cerr := probe.Close()
			rerr := os.Remove(name)
			ok := werr == nil && cerr == nil && rerr == nil
			rep.Checks = append(rep.Checks, CheckResult{
				ID: "STO-01", Name: "Datenverzeichnis schreibbar (temp+remove)", OK: ok,
				Detail: combineErrs(werr, cerr, rerr),
			})
		}
	}

	active := cfg.Policy
	if active == nil {
		p := domain.DefaultPolicy(cfg.Site.SiteID, time.Now().UTC())
		active = &p
	}
	rep.Checks = append(rep.Checks, CheckResult{
		ID: "POL-01", Name: "Policy valide", OK: active.Validate() == nil,
		Detail: errText(active.Validate()),
	})
	if active.SiteID != cfg.Site.SiteID {
		rep.Checks = append(rep.Checks, CheckResult{
			ID: "POL-02", Name: "Policy gehört zur konfigurierten Filiale", OK: false,
			Detail: "policy.site_id != site.site_id",
		})
	}

	uiOK := false
	if _, err := fs.Stat(webui.FS(), "index.html"); err == nil {
		uiOK = true
	}
	rep.Checks = append(rep.Checks, CheckResult{ID: "UI-01", Name: "Eingebettete Dashboard-Assets vorhanden", OK: uiOK})

	rep.Checks = append(rep.Checks, CheckResult{
		ID: "ADP-01", Name: "Adapter-Kinds im Binary", OK: len(shippedAdapters) > 0,
		Detail: joinComma(shippedAdapters),
	})

	// The vendor catalog is optional, but `check` must state when vendor knowledge
	// (and therefore the gate advisory and the regulatory context) is limited.
	catalog := vendorcatalog.Load(otCatalogPath())
	for _, warning := range catalog.Warnings() {
		rep.Warnings = append(rep.Warnings, warning)
	}
	switch {
	case !catalog.Enabled():
		rep.Warnings = append(rep.Warnings, "OT-Vendor-Katalog nicht geladen: Vendor-Wissen, Write-Surface-Advisory und Regulatory-Kontext sind eingeschränkt.")
	default:
		if !catalog.HasWriteSurfaces() {
			rep.Warnings = append(rep.Warnings, "OT-Vendor-Katalog ohne write-surface.json: Gate-Advisory und Schreibflaechen-Anzeige sind eingeschränkt.")
		}
		if !catalog.HasRegulatoryContext() {
			rep.Warnings = append(rep.Warnings, "OT-Vendor-Katalog ohne regulatory-context.json: Regulatory-Kontext ist eingeschränkt.")
		}
	}

	if cfg.Central != nil {
		for _, p := range []string{cfg.Central.ClientCertFile, cfg.Central.ClientKeyFile, cfg.Central.CAFile} {
			if p == "" {
				continue
			}
			if _, err := os.Stat(p); err != nil {
				rep.Checks = append(rep.Checks, CheckResult{
					ID: "CEN-01", Name: "Zentrales TLS-Material lesbar", OK: false,
					Detail: filepath.Base(p) + ": " + err.Error(),
				})
			}
		}
	}

	for _, c := range rep.Checks {
		if !c.OK {
			rep.OK = false
			return rep, nil
		}
	}
	rep.OK = true
	return rep, nil
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func combineErrs(errs ...error) string {
	var msg string
	for _, err := range errs {
		if err != nil {
			if msg != "" {
				msg += "; "
			}
			msg += err.Error()
		}
	}
	return msg
}

func joinComma(in []string) string {
	out := ""
	for i, s := range in {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

// ErrCheckFailed is returned by callers that want to signal a failed check.
var ErrCheckFailed = errors.New("self-check failed")
