// Command retail-sim is the GeDefense Retail simulator. It never talks to real
// OT devices: it starts a read-only Modbus slave, synthesizes dev-ingest events
// and writes deterministic PCAP fixtures for the test suite.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/visiongaiatechnology/gedefense/retail/internal/version"
)

func main() {
	if err := run(versionArgs(), stdoutWriter(), stderrWriter()); err != nil {
		fmt.Fprintln(stderrWriter(), "retail-sim:", err)
		exit(1)
	}
}

// run dispatches the subcommands. It is the testable entry point.
func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printUsage(stderr)
		return errors.New("missing subcommand")
	}
	switch args[0] {
	case "modbus-server":
		return runModbusServer(args[1:], stdout, stderr)
	case "feed":
		return runFeed(args[1:], stdout, stderr)
	case "pcap":
		return runPCAP(args[1:], stdout, stderr)
	case "version", "--version", "-version":
		fmt.Fprintf(stdout, "%s %s (%s, %s, commit %s)\n",
			version.Product, version.SimBinary, version.Version, version.BuildDate, version.Commit)
		return nil
	case "help", "-h", "--help":
		printUsage(stdout)
		return nil
	default:
		printUsage(stderr)
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `retail-sim - GeDefense Retail simulator (synthetic data only)

Usage:
  retail-sim modbus-server [flags]   read-only Modbus/TCP slave for adapter tests
  retail-sim feed         [flags]   synthetic events -> POST /api/v1/dev/events
  retail-sim pcap         [flags]   deterministic PCAP scenarios -> tests/testdata/pcap
  retail-sim version

modbus-server flags:
  --listen 127.0.0.1:15020   listen address (loopback recommended)
  --scenario normal|attack    register map scenario
  --unit 1                    Modbus unit id
  --read-only true            reject write function codes (always on)

feed flags:
  --url http://127.0.0.1:8080   base URL (loopback only)
  --token <bearer>              API token (or GEDEFENSE_SIM_TOKEN)
  --scenario normal|abtau|tuer|angriff|angriff-management-ui
  --duration 10                 seconds (ignored when --count is set)
  --count 0                     number of events
  --rate 20                     events per second
  --batch 50                    events per HTTP request (max 200)
  --site filiale-001 --zone zone-kaelte-1

pcap flags:
  --out ..\..\tests\testdata\pcap   output directory
  --scenario all|normal|angriff|angriff-management-ui
  --site filiale-001
`)
}

// newFlagSet builds a flag set with a bounded output writer.
func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}
