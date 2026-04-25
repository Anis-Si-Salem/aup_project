#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="$ROOT_DIR/logs"
mkdir -p "$LOG_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}[AUP]${NC} $1"; }
ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()  { echo -e "${RED}[ERROR]${NC} $1"; }

cleanup() {
    echo ""
    log "Shutting down..."
    for pid in $SERVER_PID $WEB_PID $GO_PID; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null
    ok "All processes stopped."
}
trap cleanup EXIT INT TERM

build_cpp() {
    log "Building C++ Security Core..."
    cd "$ROOT_DIR/client"
    rm -rf build
    cmake -B build 2>&1 | tee "$LOG_DIR/cpp_cmake.log"
    cmake --build build -j"$(nproc 2>/dev/null || echo 2)" 2>&1 | tee "$LOG_DIR/cpp_build.log"
    ok "C++ core built."

    log "Copying shared library to aup/lib/..."
    cp -f "$ROOT_DIR/client/build/libsecure_app_core.so" "$ROOT_DIR/aup/lib/"
    cp -f "$ROOT_DIR/client/include/license_api.h" "$ROOT_DIR/aup/lib/"
    ok "Library copied."
}

build_go() {
    log "Building Go Protected App..."
    cd "$ROOT_DIR/aup"
    export LD_LIBRARY_PATH="$ROOT_DIR/aup/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    go build -o bin/protected-app ./cmd/protected-app 2>&1 | tee "$LOG_DIR/go_build.log"
    ok "Go app built."
}

setup_vendor_server() {
    log "Setting up License Server..."
    cd "$ROOT_DIR/vendor/server"
    if [ ! -d node_modules ]; then
        npm install 2>&1 | tee "$LOG_DIR/server_npm.log"
    fi
    npx tsc 2>&1 | tee "$LOG_DIR/server_tsc.log" || true
    ok "License server ready."
}

setup_vendor_web() {
    log "Setting up Web Portal..."
    cd "$ROOT_DIR/vendor/web"
    if [ ! -d node_modules ]; then
        npm install 2>&1 | tee "$LOG_DIR/web_npm.log"
    fi
    ok "Web portal ready."
}

start_server() {
    log "Starting License Server on port 3001..."
    cd "$ROOT_DIR/vendor/server"
    npx ts-node-dev --respawn src/index.ts > "$LOG_DIR/server.log" 2>&1 &
    SERVER_PID=$!
    echo $SERVER_PID > "$LOG_DIR/server.pid"
    sleep 2
    if kill -0 "$SERVER_PID" 2>/dev/null; then
        ok "License server running (PID: $SERVER_PID)"
    else
        err "License server failed to start. Check $LOG_DIR/server.log"
        cat "$LOG_DIR/server.log"
        return 1
    fi
}

start_web() {
    log "Starting Web Portal on port 3000..."
    cd "$ROOT_DIR/vendor/web"
    npx next dev > "$LOG_DIR/web.log" 2>&1 &
    WEB_PID=$!
    echo $WEB_PID > "$LOG_DIR/web.pid"
    sleep 3
    if kill -0 "$WEB_PID" 2>/dev/null; then
        ok "Web portal running (PID: $WEB_PID)"
    else
        err "Web portal failed to start. Check $LOG_DIR/web.log"
        cat "$LOG_DIR/web.log"
        return 1
    fi
}

start_go_app() {
    log "Starting Go Protected App on port 8443..."
    cd "$ROOT_DIR/aup"
    export LD_LIBRARY_PATH="$ROOT_DIR/aup/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

    LICENSE_PATH="${LICENSE_PATH:-/etc/aup/license.json}"
    if [ ! -f "$LICENSE_PATH" ]; then
        warn "No license file at $LICENSE_PATH"
        warn "The Go app requires a valid license.json to start."
        warn "Skipping Go app startup. Set LICENSE_PATH to your license file and re-run."
        return 0
    fi

    ./bin/protected-app > "$LOG_DIR/go_app.log" 2>&1 &
    GO_PID=$!
    echo $GO_PID > "$LOG_DIR/go_app.pid"
    sleep 2
    if kill -0 "$GO_PID" 2>/dev/null; then
        ok "Go app running (PID: $GO_PID)"
    else
        err "Go app failed to start. Check $LOG_DIR/go_app.log"
        cat "$LOG_DIR/go_app.log"
        return 1
    fi
}

SERVER_PID=""
WEB_PID=""
GO_PID=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-cpp)    SKIP_CPP=1; shift ;;
        --skip-go)     SKIP_GO=1; shift ;;
        --skip-server) SKIP_SERVER=1; shift ;;
        --skip-web)    SKIP_WEB=1; shift ;;
        --build-only)  BUILD_ONLY=1; shift ;;
        --dev)         DEV_MODE=1; shift ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --skip-cpp     Skip C++ build"
            echo "  --skip-go      Skip Go build/start"
            echo "  --skip-server  Skip vendor server"
            echo "  --skip-web     Skip web portal"
            echo "  --build-only   Only build, don't start services"
            echo "  --dev          Use dev mode for server (ts-node-dev)"
            echo "  -h, --help     Show this help"
            exit 0
            ;;
        *) err "Unknown option: $1"; exit 1 ;;
    esac
done

SKIP_CPP="${SKIP_CPP:-0}"
SKIP_GO="${SKIP_GO:-0}"
SKIP_SERVER="${SKIP_SERVER:-0}"
SKIP_WEB="${SKIP_WEB:-0}"
BUILD_ONLY="${BUILD_ONLY:-0}"
DEV_MODE="${DEV_MODE:-0}"

echo "=========================================="
echo "   AUP Project - Start Everything"
echo "=========================================="
echo ""

if [ "$SKIP_CPP" -eq 0 ]; then
    build_cpp
else
    warn "Skipping C++ build."
fi

if [ "$SKIP_GO" -eq 0 ]; then
    build_go
else
    warn "Skipping Go build."
fi

if [ "$SKIP_SERVER" -eq 0 ]; then
    setup_vendor_server
else
    warn "Skipping vendor server setup."
fi

if [ "$SKIP_WEB" -eq 0 ]; then
    setup_vendor_web
else
    warn "Skipping web portal setup."
fi

if [ "$BUILD_ONLY" -eq 1 ]; then
    ok "Build-only mode. All components built."
    exit 0
fi

echo ""
echo "=========================================="
echo "   Starting Services"
echo "=========================================="
echo ""

if [ "$SKIP_SERVER" -eq 0 ]; then
    start_server
fi

if [ "$SKIP_WEB" -eq 0 ]; then
    start_web
fi

if [ "$SKIP_GO" -eq 0 ]; then
    start_go_app
fi

echo ""
echo "=========================================="
echo "   All Services Running"
echo "=========================================="
echo ""
echo "  License Server : http://localhost:3001"
echo "  Web Portal     : http://localhost:3000"
echo "  Go App         : http://localhost:8443 (if license present)"
echo ""
echo "  Logs directory : $LOG_DIR/"
echo "  Press Ctrl+C to stop all services"
echo ""

wait