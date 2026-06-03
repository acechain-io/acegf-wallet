#!/bin/bash
# Build script for WASM (Chrome Extension / Web)
#
# All release builds are hardened by default:
#   - Cargo: LTO, single codegen-unit, opt-level=z, strip, panic=abort
#   - Post-build: wasm-opt -Oz with symbol stripping
#   - Post-build: wasm-snip to remove unreachable code (if available)
#
# Prerequisites:
#   1. Install Rust: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
#   2. Add WASM target: rustup target add wasm32-unknown-unknown
#   3. Install wasm-pack: cargo install wasm-pack
#   4. Install binaryen (for wasm-opt):
#        macOS:   brew install binaryen
#        Ubuntu:  apt install binaryen
#   5. (Optional) Install wasm-snip: cargo install wasm-snip
#
# Usage:
#   ./scripts/build-wasm.sh [release|dev|profiling] [features]
#
# Examples:
#   ./scripts/build-wasm.sh release         # without ZK
#   ./scripts/build-wasm.sh release zk      # with ZK-ACE support
#
# Output:
#   pkg/                    - wasm-pack output (JS + WASM)
#   pkg/acegf_bg.wasm       - WASM binary (hardened in release)
#   pkg/acegf.js            - JS glue code
#   pkg/acegf.d.ts          - TypeScript definitions

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PROJECT_ROOT}"

# Parse arguments
BUILD_PROFILE="${1:-release}"
EXTRA_FEATURES="${2:-}"

FEATURES_FLAG=""
if [ -n "$EXTRA_FEATURES" ]; then
    FEATURES_FLAG="--features $EXTRA_FEATURES"
    echo "🌐 Building ACE-GF for WASM ($BUILD_PROFILE) with features: $EXTRA_FEATURES..."
else
    echo "🌐 Building ACE-GF for WASM ($BUILD_PROFILE)..."
fi

# Check prerequisites
if ! command -v wasm-pack &> /dev/null; then
    echo "❌ wasm-pack not found. Install it with:"
    echo "   cargo install wasm-pack"
    exit 1
fi

if ! rustup target list --installed | grep -q "wasm32-unknown-unknown"; then
    echo "📦 Adding wasm32-unknown-unknown target..."
    rustup target add wasm32-unknown-unknown
fi

# Build with wasm-pack
# --target web: for direct browser use (ES modules)
# --no-default-features: start clean, then add back features explicitly via $FEATURES_FLAG
# PQC (ML-DSA-44) is fully supported in WASM via fips204 pure Rust crate

TOOLCHAIN=$(grep 'channel' "${PROJECT_ROOT}/rust-toolchain.toml" | sed 's/.*= *"\(.*\)"/\1/')
WASM_PACK_CMD="${HOME}/.cargo/bin/rustup run ${TOOLCHAIN} ${HOME}/.cargo/bin/wasm-pack"

TOOLCHAIN=$(grep 'channel' "${PROJECT_ROOT}/rust-toolchain.toml" | sed 's/.*= *"\(.*\)"/\1/')
WASM_PACK_CMD="${HOME}/.cargo/bin/rustup run ${TOOLCHAIN} ${HOME}/.cargo/bin/wasm-pack"

case "$BUILD_PROFILE" in
    release)
        echo "📦 Building release (hardened)..."
        eval $WASM_PACK_CMD build \
            --target web \
            --release \
            --no-default-features \
            $FEATURES_FLAG
        ;;
    dev)
        echo "📦 Building dev (no hardening)..."
        eval $WASM_PACK_CMD build \
            --target web \
            --dev \
            --no-default-features \
            $FEATURES_FLAG
        ;;
    profiling)
        echo "📦 Building profiling..."
        eval $WASM_PACK_CMD build \
            --target web \
            --profiling \
            --no-default-features \
            $FEATURES_FLAG
        ;;
    bundler)
        echo "📦 Building for bundler (webpack/vite, hardened)..."
        eval $WASM_PACK_CMD build \
            --target bundler \
            --release \
            --no-default-features \
            $FEATURES_FLAG
        ;;
    *)
        echo "❌ Unknown profile: $BUILD_PROFILE"
        echo "Usage: $0 [release|dev|profiling|bundler]"
        exit 1
        ;;
esac

WASM_FILE="pkg/acegf_bg.wasm"

# ============================================
#  Post-build hardening (release/bundler only)
# ============================================

if [ "$BUILD_PROFILE" = "release" ] || [ "$BUILD_PROFILE" = "bundler" ]; then

    if [ ! -f "$WASM_FILE" ]; then
        echo "❌ WASM file not found at $WASM_FILE"
        exit 1
    fi

    ORIGINAL_SIZE=$(wc -c < "$WASM_FILE" | tr -d ' ')
    echo ""
    echo "🔒 Applying post-build hardening..."
    echo "   Pre-hardening size: $(du -h "$WASM_FILE" | cut -f1)"

    # --- Step 1: wasm-opt (binaryen) ---
    if command -v wasm-opt &> /dev/null; then
        echo "   ⏳ wasm-opt: optimizing + stripping symbols..."
        wasm-opt "$WASM_FILE" -o "$WASM_FILE" \
            -Oz \
            --enable-bulk-memory \
            --enable-mutable-globals \
            --enable-sign-ext \
            --strip-debug \
            --strip-producers \
            --zero-filled-memory \
            --remove-unused-names \
            --remove-unused-module-elements \
            --dae \
            --dae-optimizing \
            --rse \
            --vacuum \
            --duplicate-function-elimination \
            --coalesce-locals \
            --reorder-functions \
            --reorder-locals \
            --merge-blocks \
            --merge-locals \
            --simplify-locals \
            --code-folding
        echo "   ✅ wasm-opt done"
    else
        echo "   ⚠️  wasm-opt not found — skipping optimization pass"
        echo "      Install: brew install binaryen (macOS) or apt install binaryen (Ubuntu)"
    fi

    # --- Step 2: wasm-snip (remove unreachable functions) ---
    if command -v wasm-snip &> /dev/null; then
        echo "   ⏳ wasm-snip: removing unreachable code..."
        # Snip fmt infrastructure only — DO NOT snip panicking code:
        # ML-DSA-44 (fips204) relies on bounds checks that panic infrastructure provides.
        # Snipping panicking code turns those into WASM traps, breaking PQC keygen at runtime.
        wasm-snip "$WASM_FILE" -o "$WASM_FILE" \
            --snip-rust-fmt-code
        echo "   ✅ wasm-snip done"
    else
        echo "   ⚠️  wasm-snip not found — skipping snip pass"
        echo "      Install: cargo install wasm-snip"
    fi

    # --- Step 3: Final wasm-opt pass after snip ---
    if command -v wasm-opt &> /dev/null; then
        echo "   ⏳ wasm-opt: final cleanup pass..."
        wasm-opt "$WASM_FILE" -o "$WASM_FILE" \
            -Oz \
            --enable-bulk-memory \
            --enable-mutable-globals \
            --enable-sign-ext \
            --vacuum \
            --remove-unused-module-elements \
            --duplicate-function-elimination
        echo "   ✅ final pass done"
    fi

    FINAL_SIZE=$(wc -c < "$WASM_FILE" | tr -d ' ')
    SAVED=$((ORIGINAL_SIZE - FINAL_SIZE))
    if [ "$ORIGINAL_SIZE" -gt 0 ]; then
        PCT=$((SAVED * 100 / ORIGINAL_SIZE))
    else
        PCT=0
    fi

    echo ""
    echo "   📊 Hardening results:"
    echo "      Before:  $(echo "$ORIGINAL_SIZE" | awk '{printf "%'\''d", $1}') bytes"
    echo "      After:   $(echo "$FINAL_SIZE" | awk '{printf "%'\''d", $1}') bytes"
    echo "      Saved:   $(echo "$SAVED" | awk '{printf "%'\''d", $1}') bytes (${PCT}%)"
fi

echo ""
echo "✅ WASM build complete!"
echo ""
echo "Output files:"
echo "  📁 pkg/acegf_bg.wasm     - WASM binary"
echo "  📁 pkg/acegf.js          - JS glue code (ES module)"
echo "  📁 pkg/acegf.d.ts        - TypeScript definitions"
echo ""

# Show WASM file size
if [ -f "$WASM_FILE" ]; then
    WASM_SIZE=$(du -h "$WASM_FILE" | cut -f1)
    echo "📊 Final WASM binary size: $WASM_SIZE"
fi

if [ "$BUILD_PROFILE" = "release" ] || [ "$BUILD_PROFILE" = "bundler" ]; then
    echo "🔒 Hardening: LTO + strip + wasm-opt + snip applied"
else
    echo "⚡ Dev build: no hardening applied (faster builds)"
fi

echo ""
echo "Usage in JavaScript:"
echo "  import init, { generate_wasm, view_wallet_wasm } from './pkg/acegf.js';"
echo "  await init();"
echo "  const wallet = generate_wasm('my-passphrase');"
echo ""

# Copy to Chrome extension if it exists
# CHROME_EXT_DIR: configure locally
if [ -d "$CHROME_EXT_DIR" ]; then
    echo "📲 Copying to Chrome extension..."
    mkdir -p "${CHROME_EXT_DIR}/wasm"
    cp pkg/acegf_bg.wasm "${CHROME_EXT_DIR}/wasm/"
    cp pkg/acegf.js "${CHROME_EXT_DIR}/wasm/"
    cp pkg/acegf.d.ts "${CHROME_EXT_DIR}/wasm/" 2>/dev/null || true
    echo "  ✓ Copied to ${CHROME_EXT_DIR}/wasm/"
fi
