# Gecko Fork Build Guide for Windows (Quira Browser PoC)

> Research date: 2026-03-28
> Target: Build a minimal branded Firefox/Gecko fork on Windows

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Two Approaches: Full Build vs Artifact Build](#two-approaches)
3. [System Requirements](#system-requirements)
4. [Approach A: Surfer-based Fork (Recommended for PoC)](#approach-a-surfer-based-fork)
5. [Approach B: Raw Mozilla Build System](#approach-b-raw-mozilla-build-system)
6. [How Existing Forks Handle This](#how-existing-forks-handle-this)
7. [Minimum Branding Changes](#minimum-branding-changes)
8. [Timeline Estimate](#timeline-estimate)
9. [Risk Assessment](#risk-assessment)

---

## Executive Summary

Building a Gecko fork on Windows is well-documented but resource-intensive. The fastest path to a branded PoC is using **Zen Browser's "surfer" tool** (`@zen-browser/surfer`), which automates Firefox source downloading, patch management, branding, and building. A minimal branded build with surfer can be achieved in approximately **4-8 hours of wall-clock time** (most of which is compilation), with roughly **1-2 hours of actual developer work**.

There are two distinct approaches used by existing forks:

| Fork | Approach | Build Tool | Base |
|------|----------|------------|------|
| **Zen Browser** | Full source build with surfer | `@zen-browser/surfer` (npm) | Firefox Stable (currently 149.0) |
| **Floorp (v12+)** | Pre-built runtime + overlay | Custom Deno tool (`feles-build`) | Downloads pre-built Firefox runtime artifact |
| **LibreWolf** | Patch-based source build | Shell scripts + CI | Firefox ESR |
| **Mercury** | Compiler-optimized source build | Custom scripts | Firefox + LibreWolf patches |

---

## Two Approaches

### Full Source Build (Zen/LibreWolf style)
- Download Firefox source code
- Apply patches + branding
- Compile everything from source with `./mach build`
- **Pros**: Full control over every aspect, can modify C++/Rust engine code
- **Cons**: 40+ GB disk, 1-3 hours compile time, complex toolchain

### Artifact/Overlay Build (Floorp v12 style)
- Download a pre-built Firefox runtime binary
- Overlay custom chrome (UI), extensions, preferences
- **Pros**: Much faster (~minutes), smaller disk footprint, easier iteration
- **Cons**: Cannot modify compiled engine code, limited to UI/preference/extension changes

**Recommendation for Quira PoC**: Start with **surfer full build** for maximum future flexibility. If the goal is purely UI/branding validation, consider the Floorp-style artifact approach.

---

## System Requirements

### Hardware
| Resource | Minimum | Recommended |
|----------|---------|-------------|
| RAM | 8 GB | 16-32 GB |
| Disk | 40 GB free | 80+ GB free (SSD strongly recommended) |
| CPU | 4 cores | 8+ cores (build is parallelizable) |

### Software Prerequisites
| Tool | Version/Details | Install |
|------|-----------------|---------|
| **Windows** | 10 or 11 with latest updates | - |
| **MozillaBuild** | 4.2+ | `https://ftp.mozilla.org/pub/mozilla/libraries/win32/MozillaBuildSetup-Latest.exe` |
| **Visual Studio** | 2022 or 2025 (Build Tools suffice) | VS Installer with "Desktop development with C++" workload |
| **Git** | Latest | `winget install Git.Git` |
| **Node.js** | 18+ (check `.nvmrc` of target project) | `winget install OpenJS.NodeJS.LTS` |
| **Python** | 3.11+ | Bundled with MozillaBuild, or `winget install Python.Python.3.12` |
| **Rust** | Latest stable | `rustup` (installed via `mach bootstrap`) |

### Antivirus Exclusions (Critical for Performance)
Add these directories to Windows Defender / antivirus exclusions:
- `C:\mozilla-build`
- Your source directory (e.g., `F:\gecko-fork`)
- `%USERPROFILE%\.mozbuild`

Without exclusions, builds can be **2-5x slower** due to real-time scanning.

---

## Approach A: Surfer-based Fork (Recommended for PoC)

### What is Surfer?

Surfer (`@zen-browser/surfer`) is an npm CLI tool created by the Zen Browser team that automates:
- Downloading Firefox source archives
- Initializing the source as a git repo
- Applying/exporting patches
- Generating branding assets from config
- Running `./mach build` with proper mozconfig
- Packaging the final browser

Repository: `https://github.com/zen-browser/surfer`
NPM: `@zen-browser/surfer` (v1.13.4)
Lineage: Forked from Gluon (which came from Melon/Dot Browser)

### Step-by-Step: Create a Minimal Fork with Surfer

#### 1. Install Prerequisites

```powershell
# Install MozillaBuild (run as Administrator)
Invoke-WebRequest -Uri "https://ftp.mozilla.org/pub/mozilla/libraries/win32/MozillaBuildSetup-Latest.exe" -OutFile "C:\MozillaBuildSetup-Latest.exe"
Start-Process "C:\MozillaBuildSetup-Latest.exe" -ArgumentList "/S" -Wait

# Install Node.js LTS (if not already installed)
winget install OpenJS.NodeJS.LTS

# Install Git (if not already installed)
winget install Git.Git

# Install Rust targets
rustup target add x86_64-pc-windows-msvc
rustup target add aarch64-pc-windows-msvc
```

#### 2. Create Project Directory

```bash
# Use MozillaBuild shell: C:\mozilla-build\start-shell.bat
# Or use Git Bash / standard terminal

mkdir -p F:/gecko-fork/quira-browser
cd F:/gecko-fork/quira-browser
npm init -y
npm install @zen-browser/surfer
```

#### 3. Initialize Project with Surfer

```bash
npx surfer setup-project
```

This interactive wizard asks for:
- **Product**: Firefox stable (recommended) or ESR
- **Version**: Latest Firefox version (auto-detected)
- **Product name**: `Quira Browser`
- **Binary name**: `quira`
- **Vendor**: `Quira Project`
- **App ID**: `app.quira-browser`
- **UI mode**: None (or UserChrome for CSS customization)

This creates a `surfer.json` config file. Example:

```json
{
  "name": "Quira Browser",
  "vendor": "Quira Project",
  "appId": "app.quira-browser",
  "binaryName": "quira",
  "version": {
    "product": "firefox",
    "version": "149.0"
  },
  "buildOptions": {
    "windowsUseSymbolicLinks": false
  }
}
```

#### 4. Download Firefox Source

```bash
npx surfer download
```

This downloads the Firefox source archive (~500 MB compressed) and extracts it to an `engine/` directory (~4 GB extracted). It then initializes a git repo inside `engine/` for patch tracking.

**Expected time**: 5-15 minutes depending on connection speed.

#### 5. Bootstrap Build Dependencies

```bash
npx surfer bootstrap
```

This runs `./mach bootstrap --application-choice browser` inside the engine directory, which:
- Installs the correct Rust toolchain
- Downloads prebuilt Clang/LLVM
- Installs required Python packages
- Sets up sccache for faster rebuilds
- Configures Visual Studio paths

**Expected time**: 10-30 minutes (downloads ~2 GB of toolchain files to `~/.mozbuild`).

#### 6. Add Branding (Minimal)

Create branding assets in `configs/branding/release/`:

```
configs/branding/release/
├── firefox.ico          # Main application icon (256x256 multi-res ICO)
├── firefox64.ico        # 64px icon variant
├── document.ico         # Document association icon
├── logo.png             # Various sizes: 16, 22, 24, 32, 48, 64, 128, 256, 512, 1024
├── logo16.png
├── logo22.png
├── logo24.png
├── logo32.png
├── logo48.png
├── logo64.png
├── logo128.png
├── logo256.png
├── logo512.png
├── logo1024.png
├── VisualElements_70.png
├── VisualElements_150.png
└── content/
    └── (optional about dialog assets)
```

**Shortcut for PoC**: Copy Firefox's default branding icons and just change colors. Surfer can auto-generate branding if `buildOptions.generateBranding` is set to `true` in `surfer.json`:

```json
{
  "buildOptions": {
    "generateBranding": true
  },
  "brands": {
    "release": {
      "backgroundColor": "#1a1a2e",
      "brandShorterName": "Quira",
      "brandShortName": "Quira",
      "brandFullName": "Quira Browser"
    }
  }
}
```

#### 7. Configure mozconfig

Create `configs/common/mozconfig`:

```makefile
ac_add_options --with-app-name=${binName}
export MOZ_USER_DIR="Quira"
export MOZ_APP_VENDOR="Quira Project"
export MOZ_APP_BASENAME=${binName}
export MOZ_APP_PROFILE=${binName}
export MOZ_DISTRIBUTION_ID=${appId}

export MOZ_STUB_INSTALLER=1
export MOZ_INCLUDE_SOURCE_INFO=1
export MOZ_SOURCE_REPO=https://github.com/example/quira-browser
export MOZ_SOURCE_CHANGESET=${changeset}

ac_add_options --enable-bootstrap
ac_add_options --enable-application=browser

# Disable telemetry
mk_add_options MOZ_TELEMETRY_REPORTING=
mk_add_options MOZ_DATA_REPORTING=

# Allow unsigned extensions
export MOZ_REQUIRE_SIGNING=
mk_add_options MOZ_REQUIRE_SIGNING=
ac_add_options --with-unsigned-addon-scopes=app,system
```

Create `configs/windows/mozconfig`:

```makefile
ac_add_options --target=x86_64-pc-windows-msvc
ac_add_options --disable-maintenance-service
ac_add_options --disable-bits-download
ac_add_options --without-ccache
```

#### 8. Build

```bash
# Run from MozillaBuild shell for best compatibility
npx surfer build
```

This:
1. Merges common + platform mozconfig
2. Writes version info
3. Runs `./mach build` inside the engine directory

**Expected time**:
- First build: **1-3 hours** (depending on CPU/RAM)
- Subsequent builds (with sccache): **5-30 minutes**

#### 9. Run the Browser

```bash
npx surfer run
```

Or directly:

```bash
cd engine && ./mach run
```

#### 10. Package for Distribution

```bash
npx surfer package
```

This runs `./mach package` to create distributable archives.

---

## Approach B: Raw Mozilla Build System

If you prefer not to use surfer and want full control:

```bash
# 1. Install MozillaBuild
# Download from https://ftp.mozilla.org/pub/mozilla/libraries/win32/MozillaBuildSetup-Latest.exe

# 2. Open MozillaBuild shell
C:\mozilla-build\start-shell.bat

# 3. Get source
cd /c/
mkdir mozilla-source && cd mozilla-source
wget https://raw.githubusercontent.com/mozilla-firefox/firefox/refs/heads/main/python/mozboot/bin/bootstrap.py
python3 bootstrap.py
# Select: Firefox for Desktop

# 4. Bootstrap
cd firefox
./mach bootstrap

# 5. Create .mozconfig in the firefox root
cat > .mozconfig << 'EOF'
ac_add_options --with-app-name=quira
ac_add_options --enable-application=browser
ac_add_options --disable-tests
ac_add_options --enable-optimize
ac_add_options --target=x86_64-pc-windows-msvc

export MOZ_APP_BASENAME=Quira
export MOZ_APP_VENDOR="Quira Project"
export MOZ_DISTRIBUTION_ID=app.quira-browser

mk_add_options MOZ_TELEMETRY_REPORTING=
mk_add_options MOZ_DATA_REPORTING=
EOF

# 6. Build
./mach build

# 7. Run
./mach run

# 8. Package
./mach package
```

**Note**: This approach skips the patch management and branding automation that surfer provides. You would manually manage changes to the source tree.

---

## How Existing Forks Handle This

### Zen Browser
- **Tool**: `@zen-browser/surfer` (npm)
- **Config**: `surfer.json` at project root
- **Structure**:
  ```
  zen-browser/desktop/
  ├── surfer.json          # Version, branding, build config
  ├── configs/
  │   ├── common/mozconfig # Shared build flags
  │   ├── windows/mozconfig # Windows-specific flags
  │   ├── linux/mozconfig
  │   ├── macos/mozconfig
  │   └── branding/        # Icon assets per brand
  │       ├── release/
  │       └── twilight/
  ├── src/                 # Custom source patches/additions
  ├── scripts/             # Build automation scripts
  └── build/
      └── windows/
          ├── bootstrap.ps1     # CI bootstrap
          └── firefox_update.ps1
  ```
- **Workflow**: `npm run init` = download + import patches + bootstrap; `npm run build` = `surfer build`
- **Key insight**: Surfer manages Firefox source in an `engine/` directory with git, enabling patch import/export workflow

### Floorp (v12+, "Noraneko")
- **Tool**: Custom Deno-based `feles-build.ts`
- **Approach**: Downloads **pre-built Firefox runtime** from `dev-assets.floorp.app`, then overlays custom features
- **Structure**:
  ```
  Floorp-Projects/Floorp/
  ├── deno.json             # Tasks: feles-build, dev-tool
  ├── tools/
  │   ├── feles-build.ts    # Main build orchestrator
  │   └── src/
  │       ├── initializer.ts  # Downloads runtime binary
  │       ├── builder.ts      # Builds overlay UI
  │       ├── patcher.ts      # Applies patches
  │       ├── symlinker.ts    # Links custom code into runtime
  │       └── injector.ts     # Injects custom XHTML/JS
  ├── browser-features/     # Custom browser features (SolidJS + Tailwind)
  ├── bridge/               # Loader modules connecting to Gecko
  └── static/gecko/pref/    # Custom preference overrides
  ```
- **Key insight**: Floorp does NOT compile Gecko from source. It downloads a pre-compiled runtime and adds features on top via overlays, symlinks, and XUL/XHTML injection. This is much faster for iteration but limits engine-level changes.

### LibreWolf
- **Approach**: Maintains a set of `.patch` files applied to Firefox ESR source
- **Hosted on**: Codeberg (not GitHub)
- **Key files**: Series of patch files + `librewolf.cfg` (autoconfig) + custom `distribution/policies.json`
- **Focus**: Privacy/security hardening via preferences and patch removal of telemetry

---

## Minimum Branding Changes

For the absolute minimum "it's not Firefox anymore" branded build:

1. **`surfer.json`**: Set name, vendor, appId, binaryName
2. **mozconfig**: Set `--with-app-name`, `MOZ_APP_BASENAME`, `MOZ_APP_VENDOR`
3. **Icons**: At minimum, replace `firefox.ico` and `firefox64.ico` with custom icons
4. **About dialog**: Optional; modify `browser/base/content/aboutDialog.xhtml` via a patch

With surfer's `generateBranding: true`, steps 3 and 4 can be partially automated.

**Estimated developer time for minimum branding**: 30-60 minutes of work (excluding compile time).

---

## Timeline Estimate

### Day 1 PoC Plan

| Task | Developer Time | Wall Clock |
|------|---------------|------------|
| Install prerequisites (MozillaBuild, VS Build Tools, Node, Git) | 15 min | 30-60 min |
| Set up surfer project (`setup-project`) | 10 min | 10 min |
| Download Firefox source (`surfer download`) | 2 min | 10-20 min |
| Bootstrap toolchain (`surfer bootstrap`) | 5 min | 15-30 min |
| Create minimal branding + mozconfig | 30 min | 30 min |
| First build (`surfer build`) | 5 min | 1-3 hours |
| Verify and run | 10 min | 10 min |
| **Total** | **~1.5 hours** | **~3-5 hours** |

This is achievable in a single work day. The longest step is compilation, during which you can work on other things.

### Subsequent Iteration
- UI-only changes: `surfer build --ui` (5-15 min)
- Full rebuild with sccache: 10-30 min
- Incremental rebuild after small C++ change: 5-15 min

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Build fails due to VS version mismatch | Medium | High | Use `./mach bootstrap` which auto-detects; or use VS 2022 Build Tools |
| Disk space insufficient | Medium | High | Ensure 80+ GB free; use SSD |
| Antivirus slows build to crawl | High | Medium | Add exclusions before building |
| Surfer bugs on Windows | Low-Medium | Medium | Surfer is actively maintained; Zen builds on Windows in CI |
| Firefox version update breaks patches | Medium | Medium | Pin to specific FF version; update incrementally |
| Licensing compliance | Low | High | Must not use Firefox trademarks; surfer has license check built in (`surfer license-check`) |

---

## Key Commands Reference

```bash
# Surfer CLI
npx surfer setup-project      # Interactive project setup
npx surfer download            # Download Firefox source
npx surfer bootstrap           # Install build dependencies via mach
npx surfer import              # Apply patches from src/ to engine/
npx surfer build               # Full build
npx surfer build --ui          # UI-only fast rebuild
npx surfer run                 # Launch the browser
npx surfer package             # Package for distribution
npx surfer export <file>       # Export a changed file as patch
npx surfer status              # Show changed files in engine/
npx surfer reset               # Reset engine to stock Firefox
npx surfer license-check       # Check MPL-2.0 headers
npx surfer ff-version          # Show Firefox version being built against

# Direct mach commands (inside engine/)
cd engine
./mach build                   # Build
./mach build faster            # Incremental UI build
./mach run                     # Run browser
./mach run --debug             # Run with debugger
./mach package                 # Create distributable package
./mach clobber                 # Clean build artifacts
./mach bootstrap               # Re-bootstrap dependencies
```

---

## Next Steps for Quira

1. Set up the build environment on a development machine
2. Create a minimal branded build using surfer to validate the pipeline
3. Decide on fork depth: UI-only (Floorp-style) vs full engine (Zen-style)
4. Set up CI/CD (GitHub Actions) for automated builds
5. Establish a patch management workflow for tracking upstream Firefox updates
6. Address Mozilla trademark/licensing requirements before any public distribution
