# Third-party notices

GeDefense Retail is deliberately small: the runtime is written in Go using **only the Go standard
library**, with no CGO and no external Go modules. This file lists the components and assets that
are relevant for redistribution and attribution.

## Go standard library

- Copyright 2009 The Go Authors. All rights reserved.
- License: BSD 3-Clause (see the Go distribution / <https://go.dev/LICENSE>).
- Usage: compiled into the `retaild`, `retailgate` and `retail-sim` binaries. Go's standard
  library includes code derived from third parties; those notices are part of the Go distribution.
- No Go modules are vendored in this repository.

## Web UI

- No third-party JavaScript frameworks, icon packs, CSS libraries, web fonts or CDN resources.
- The interface uses a system font stack and local assets only.
- All UI code is part of this repository and is covered by the repository license.

## Brand assets (VisionGaiaTechnology)

| Asset | Origin | Notes |
|---|---|---|
| `docs/assets/gedefense-logo.png` | Original VisionGaiaTechnology material | Logo, not third-party; not from a CDN |
| `docs/assets/sirdu-512.png` | Original VisionGaiaTechnology material | Mascot, not third-party; used locally by the UI |

These assets are **not** third-party works. They are distributed with the repository for
project-related use; trademark rights are not granted by the software license (see
[NOTICE](NOTICE)).

## Test and build tooling (not shipped at runtime)

- Python scripts in the source test harness use the Python standard library only.
- The build scripts use the Go toolchain and PowerShell/Bash; they are not part of the runtime
  binaries.

## No CDN, no telemetry

The software makes no external requests from the dashboard, loads no external assets, and does not
include a telemetry or analytics SDK.

If a future release adds third-party components, they will be listed here with version, license and
source before release.
