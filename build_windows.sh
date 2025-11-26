#!/bin/bash
# Windows Build Script
# Run this on Windows to cross-compile or natively build Option B & C payloads

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

# Create dataset/PE directory if it doesn't exist
mkdir -p dataset/PE

# Gather build info
RUSTC_VER=$(rustc --version | awk '{print $2}' 2>/dev/null || echo "unknown")
TS=$(date +%Y%m%d%H%M%S)
PLATFORM=$(uname -s)

echo "=== Building Windows Payloads (Option B & C) ==="
echo "Platform: $PLATFORM"
echo "Rustc: $RUSTC_VER"
echo "Timestamp: $TS"
echo ""

# Build and copy function
build_and_copy() {
  CRATE_MANIFEST="$1"
  OUT_BASE="$2"
  
  if [ ! -f "$CRATE_MANIFEST" ]; then
    echo "ERROR: Manifest not found: $CRATE_MANIFEST"
    return 1
  fi

  PKG_DIR=$(dirname "$CRATE_MANIFEST")
  PKG_NAME=$(basename "$PKG_DIR")

  echo "Building $PKG_NAME (release + debug)..."

  # Build release
  cargo build --manifest-path "$CRATE_MANIFEST" --release

  # Build debug
  cargo build --manifest-path "$CRATE_MANIFEST"

  # Determine target directory (assume native build on Windows)
  # On Windows with native Rust, target is just target/release and target/debug
  RELEASE_PATH="$PKG_DIR/target/release"
  DEBUG_PATH="$PKG_DIR/target/debug"

  # Find release artifact
  if [ -f "$RELEASE_PATH/$PKG_NAME.exe" ]; then
    REL_FILE="$RELEASE_PATH/$PKG_NAME.exe"
    REL_EXT="exe"
  elif [ -f "$RELEASE_PATH/$PKG_NAME.dll" ]; then
    REL_FILE="$RELEASE_PATH/$PKG_NAME.dll"
    REL_EXT="dll"
  else
    echo "ERROR: Release artifact not found for $PKG_NAME"
    ls -la "$RELEASE_PATH" 2>/dev/null || echo "Directory not found: $RELEASE_PATH"
    return 1
  fi

  # Find debug artifact
  if [ -f "$DEBUG_PATH/$PKG_NAME.exe" ]; then
    DBG_FILE="$DEBUG_PATH/$PKG_NAME.exe"
    DBG_EXT="exe"
  elif [ -f "$DEBUG_PATH/$PKG_NAME.dll" ]; then
    DBG_FILE="$DEBUG_PATH/$PKG_NAME.dll"
    DBG_EXT="dll"
  else
    echo "ERROR: Debug artifact not found for $PKG_NAME"
    ls -la "$DEBUG_PATH" 2>/dev/null || echo "Directory not found: $DEBUG_PATH"
    return 1
  fi

  # Copy to dataset/PE with descriptive names
  REL_DEST="dataset/PE/${OUT_BASE}_windows_x86_64_release_rust${RUSTC_VER}_${TS}.${REL_EXT}"
  DBG_DEST="dataset/PE/${OUT_BASE}_windows_x86_64_debug_rust${RUSTC_VER}_${TS}.${DBG_EXT}"

  cp "$REL_FILE" "$REL_DEST"
  cp "$DBG_FILE" "$DBG_DEST"

  echo "  Copied: $REL_DEST"
  echo "  Copied: $DBG_DEST"
}

# Build and copy each crate
echo "Building payload_dll..."
build_and_copy "src/apc_injection/option_b/payload_dll/Cargo.toml" "apc_optionb_payload_dll" || echo "WARNING: payload_dll build failed"

echo ""
echo "Building dll_loader..."
build_and_copy "src/apc_injection/option_b/dll_loader/Cargo.toml" "apc_optionb_dll_loader" || echo "WARNING: dll_loader build failed"

echo ""
echo "Building ipc_payload..."
build_and_copy "src/apc_injection/option_c/ipc_payload/Cargo.toml" "apc_optionc_ipc_payload" || echo "WARNING: ipc_payload build failed"

echo ""
echo "Building ipc_loader..."
build_and_copy "src/apc_injection/option_c/ipc_loader/Cargo.toml" "apc_optionc_ipc_loader" || echo "WARNING: ipc_loader build failed"

echo ""
echo "=== Build Complete ==="
echo "Artifacts copied to: dataset/PE/"
ls -la dataset/PE
