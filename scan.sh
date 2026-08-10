#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Secure SDLC — Universal Scanner
# ============================================================
# Run all 6 security scanners against any repository.
#
# Usage:
#   ./scan.sh                          # Scan current directory
#   ./scan.sh /path/to/any/repo        # Scan a specific repo
#   ./scan.sh --quick                  # Skip slow scanners (ZAP, image build)
#   ./scan.sh --scanner=sast           # Run only one scanner
#
# Scanners run (auto-detected based on what's in the repo):
#   1. Gitleaks    — secrets in git history (always runs)
#   2. Semgrep     — static analysis (language auto-detected)
#   3. Trivy FS    — dependency scanning (lockfile auto-detected)
#   4. Trivy Image — container scanning (if Dockerfile found)
#   5. Trivy Config — IaC misconfig scanning (always runs)
#   6. ZAP         — runtime DAST (if the app can start)
#
# Prerequisites (install what you need):
#   brew install gitleaks semgrep trivy   # macOS
#   apt install gitleaks                  # Linux — then pip install semgrep
#   docker pull zaproxy/zap-stable        # only if using --with-dast
# ============================================================

# ── Configuration ────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

TARGET_DIR="."
QUICK_MODE=false
SINGLE_SCANNER=""
WITH_DAST=false
FAILED=0
PASSED=0
SKIPPED=0

# ── Parse arguments ──────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case $1 in
        --quick) QUICK_MODE=true; shift ;;
        --with-dast) WITH_DAST=true; shift ;;
        --scanner=*) SINGLE_SCANNER="${1#*=}"; shift ;;
        --scanner) SINGLE_SCANNER="$2"; shift 2 ;;
        -h|--help)
            head -30 "$0" | grep -E "^#" | sed 's/^# \?//'
            exit 0
            ;;
        *) TARGET_DIR="$1"; shift ;;
    esac
done

if [[ ! -d "$TARGET_DIR" ]]; then
    echo -e "${RED}Error: Directory not found: $TARGET_DIR${NC}"
    exit 1
fi

TARGET_DIR="$(cd "$TARGET_DIR" && pwd)"
REPO_NAME="$(basename "$TARGET_DIR")"

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Secure SDLC Scan — $REPO_NAME${NC}"
echo -e "${CYAN}  Target: $TARGET_DIR${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

# ── Load config file ─────────────────────────────────────────

CONFIG_FILE="$TARGET_DIR/.sec-sdlc.yml"
CONFIG_LANGUAGE=""
CONFIG_EXCLUDE_RULES=""
CONFIG_SKIP_SCANNERS=""

if [[ -f "$CONFIG_FILE" ]]; then
    echo -e "${CYAN}  Config:${NC} .sec-sdlc.yml found"
    # Extract values using simple grep (no yq dependency)
    CONFIG_LANGUAGE=$(grep -E '^\s*language:' "$CONFIG_FILE" 2>/dev/null | head -1 | sed 's/.*language:\s*//' | tr -d '"' | tr -d "'" || echo "")
    CONFIG_SKIP_SCANNERS=$(grep -A10 '^skip:' "$CONFIG_FILE" 2>/dev/null | grep '^\s*-' | sed 's/.*-\s*//' | tr '\n' ',' || echo "")
fi

# ── Auto-detect project type ────────────────────────────────

detect_language() {
    # Config file overrides auto-detection
    if [[ -n "$CONFIG_LANGUAGE" ]]; then echo "$CONFIG_LANGUAGE"; return 0; fi

    if [[ -f "$TARGET_DIR/package.json" ]]; then echo "javascript"; return 0; fi
    if [[ -f "$TARGET_DIR/requirements.txt" ]] || [[ -f "$TARGET_DIR/pyproject.toml" ]]; then echo "python"; return 0; fi
    if [[ -f "$TARGET_DIR/pom.xml" ]] || [[ -f "$TARGET_DIR/build.gradle" ]]; then echo "java"; return 0; fi
    if [[ -f "$TARGET_DIR/composer.json" ]]; then echo "php"; return 0; fi
    if [[ -f "$TARGET_DIR/go.mod" ]]; then echo "go"; return 0; fi
    if [[ -f "$TARGET_DIR/Gemfile" ]]; then echo "ruby"; return 0; fi
    if [[ -f "$TARGET_DIR/Cargo.toml" ]]; then echo "rust"; return 0; fi
    if [[ -f "$TARGET_DIR/.NET" ]] || ls "$TARGET_DIR"/*.csproj &>/dev/null; then echo "csharp"; return 0; fi
    echo "generic"
}

detect_dockerfile() {
    if [[ -f "$TARGET_DIR/Dockerfile" ]]; then echo "true"; else echo "false"; fi
}

detect_start_command() {
    # Check config file first
    local cmd=$(grep -E '^\s*start_command:' "$CONFIG_FILE" 2>/dev/null | sed 's/.*start_command:\s*//' | tr -d '"' | tr -d "'" || echo "")
    if [[ -n "$cmd" ]]; then echo "$cmd"; return 0; fi

    # Auto-detect
    if [[ -f "$TARGET_DIR/package.json" ]]; then echo "node app.js"; return 0; fi
    if [[ -f "$TARGET_DIR/app.py" ]]; then echo "python3 app.py"; return 0; fi
    if [[ -f "$TARGET_DIR/manage.py" ]]; then echo "python3 manage.py runserver"; return 0; fi
    echo ""
}

LANGUAGE=$(detect_language)
HAS_DOCKERFILE=$(detect_dockerfile)
START_CMD=$(detect_start_command)

echo -e "${CYAN}  Detected:${NC} $LANGUAGE"
echo -e "${CYAN}  Dockerfile:${NC} $HAS_DOCKERFILE"
echo ""

# ── Helper functions ─────────────────────────────────────────

run_scanner() {
    local name="$1"
    local command="$2"

    # Skip if single scanner mode and this isn't it
    if [[ -n "$SINGLE_SCANNER" && "$SINGLE_SCANNER" != "$name" ]]; then
        echo -e "  ${YELLOW}⏭${NC}  $name (skipped — running only $SINGLE_SCANNER)"
        ((SKIPPED++)) || true
        return 0
    fi

    echo -e "  ${CYAN}→${NC}  $name..."

    if eval "$command" &>/tmp/scan-output.txt; then
        echo -e "  ${GREEN}✅${NC} $name — passed"
        ((PASSED++)) || true
    else
        local exit_code=$?
        echo -e "  ${RED}❌${NC} $name — found issues (exit code $exit_code)"
        # Show summary of findings
        if [[ -s /tmp/scan-output.txt ]]; then
            grep -E "finding|vuln|CRITICAL|HIGH|secret|error" /tmp/scan-output.txt 2>/dev/null | head -10 | while read line; do
                echo -e "     ${RED}→${NC} $line"
            done
        fi
        ((FAILED++)) || true
    fi
    echo ""
}

require_tool() {
    if ! command -v "$1" &>/dev/null; then
        echo -e "  ${YELLOW}⏭${NC}  $2 (skipped — $1 not installed)"
        ((SKIPPED++)) || true
        return 1
    fi
    return 0
}

# ── Scanner 1: Gitleaks (secrets) ────────────────────────────

run_secret_scan() {
    require_tool gitleaks "Secret Scan" || return 0
    run_scanner "secret-scan" \
        "cd '$TARGET_DIR' && gitleaks detect --source . --verbose 2>&1"
}

# ── Scanner 2: Semgrep (SAST) ────────────────────────────────

run_sast() {
    require_tool semgrep "SAST" || return 0

    local ruleset="p/$LANGUAGE"
    case "$LANGUAGE" in
        generic) ruleset="p/default" ;;
        csharp) ruleset="p/csharp" ;;
    esac

    run_scanner "sast" \
        "cd '$TARGET_DIR' && semgrep scan --config '$ruleset' --error . 2>&1"
}

# ── Scanner 3: Trivy FS (dependencies) ───────────────────────

run_sca() {
    require_tool trivy "SCA" || return 0

    run_scanner "sca" \
        "cd '$TARGET_DIR' && trivy fs --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --no-progress . 2>&1"
}

# ── Scanner 4: Trivy Image (container) ───────────────────────

run_container_scan() {
    if [[ "$HAS_DOCKERFILE" != "true" ]]; then
        echo -e "  ${YELLOW}⏭${NC}  container-scan (skipped — no Dockerfile found)"
        ((SKIPPED++)) || true
        return 0
    fi

    if [[ "$QUICK_MODE" == true ]]; then
        echo -e "  ${YELLOW}⏭${NC}  container-scan (skipped — quick mode)"
        ((SKIPPED++)) || true
        return 0
    fi

    require_tool trivy "Container Scan" || return 0

    local image_tag="sec-sdlc-scan-$$"
    docker build -t "$image_tag" "$TARGET_DIR" &>/dev/null

    run_scanner "container-scan" \
        "trivy image --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --no-progress '$image_tag' 2>&1"

    docker rmi "$image_tag" &>/dev/null
}

# ── Scanner 5: Trivy Config (IaC) ────────────────────────────

run_config_scan() {
    require_tool trivy "Config Scan" || return 0

    run_scanner "config-scan" \
        "cd '$TARGET_DIR' && trivy config --severity HIGH,CRITICAL --no-progress . 2>&1"
}

# ── Scanner 6: ZAP (DAST) ────────────────────────────────────

run_dast() {
    if [[ "$WITH_DAST" != "true" ]]; then
        echo -e "  ${YELLOW}⏭${NC}  dast (skipped — use --with-dast to enable)"
        ((SKIPPED++)) || true
        return 0
    fi

    if [[ -z "$START_CMD" ]]; then
        echo -e "  ${YELLOW}⏭${NC}  dast (skipped — couldn't detect start command)"
        ((SKIPPED++)) || true
        return 0
    fi

    require_tool docker "DAST" || return 0

    echo -e "  ${CYAN}→${NC}  dast — starting app: $START_CMD"
    cd "$TARGET_DIR"
    eval "$START_CMD" &
    local app_pid=$!
    sleep 5

    if ! kill -0 $app_pid 2>/dev/null; then
        echo -e "  ${RED}❌${NC} dast — app failed to start"
        ((FAILED++)) || true
        return 0
    fi

    run_scanner "dast" \
        "docker run --network host -v '$TARGET_DIR':/zap/wrk:ro zaproxy/zap-stable zap-baseline.py -t http://localhost:3000 -r /zap/wrk/zap-report.html 2>&1"

    kill $app_pid 2>/dev/null
    wait $app_pid 2>/dev/null
}

# ── Run all scanners ─────────────────────────────────────────

if [[ -n "$SINGLE_SCANNER" ]]; then
    echo -e "${CYAN}  Running single scanner: $SINGLE_SCANNER${NC}"
    echo ""
fi

run_secret_scan
run_sast
run_sca
run_config_scan
run_container_scan
run_dast

# ── Summary ──────────────────────────────────────────────────

echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}Passed:${NC}  $PASSED"
echo -e "  ${RED}Failed:${NC}  $FAILED"
echo -e "  ${YELLOW}Skipped:${NC} $SKIPPED"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

if [[ $FAILED -gt 0 ]]; then
    echo ""
    echo -e "${RED}  Some scanners found issues. Review the output above.${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}  All scanners passed.${NC}"
exit 0
