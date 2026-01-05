#!/bin/bash

SCRIPT_PATH=$(realpath "$0")
GHIDRA_DIR=$(dirname "$SCRIPT_PATH")
ROOT_DIR=$(dirname "$GHIDRA_DIR")

GRADLEW="$ROOT_DIR/gradlew"
PATCHES_DIR="$ROOT_DIR/patches"
CLI_JAR=$(find "$ROOT_DIR" -maxdepth 1 -name "revanced-cli-*-all.jar" | head -n 1)
GHIDRA_SCRIPT="$GHIDRA_DIR/NativePatch.py"
KEYSTORE="$GHIDRA_DIR/my-release-key.keystore"
APP_SOURCE="$GHIDRA_DIR/app_source"

if [ "$#" -ne 1 ]; then
    echo "Usage: ./patch-eds.sh <path_to_apk>"
    exit 1
fi

APK_IN=$(realpath "$1")
BASE_PATCHED="$GHIDRA_DIR/base_patched.apk"
ALIGNED_APK="$GHIDRA_DIR/aligned.apk"
APK_OUT="$GHIDRA_DIR/projecteds-final-patched.apk"

SDK_ROOT="${ANDROID_HOME:-$HOME/Android/Sdk}"
BUILD_TOOLS_DIR=$(ls -d $SDK_ROOT/build-tools/* 2>/dev/null | sort -V | tail -n 1)
ZIPALIGN="$BUILD_TOOLS_DIR/zipalign"
APKSIGNER="$BUILD_TOOLS_DIR/apksigner"

for tool in "$GRADLEW" "$CLI_JAR" "$ZIPALIGN" "$APKSIGNER" ghidra-analyzeHeadless; do
    if [ ! -f "$tool" ] && ! command -v "$tool" &> /dev/null; then
        echo "[-] Error: Missing required tool or file: $tool"
        exit 1
    fi
done

echo "[*] Step 1: Building ReVanced patches..."
cd "$ROOT_DIR"
"$GRADLEW" :patches:apiDump
"$GRADLEW" build
PATCHES_RVP=$(find "$PATCHES_DIR/build/libs/" -name "patches-*.rvp" | head -n 1)

if [ -z "$PATCHES_RVP" ]; then
    echo "[-] Error: Could not find built .rvp file."
    exit 1
fi

if [ ! -f "$KEYSTORE" ]; then
    echo "[*] Step 2: Generating keystore..."
    keytool -genkey -v -keystore "$KEYSTORE" -alias portable -keyalg RSA -keysize 2048 -validity 10000 \
        -storepass password -keypass password -dname "CN=User, OU=ReVanced, O=OpenSource, L=Unknown, ST=Unknown, C=XX"
fi

echo "[*] Step 3: Decompiling for native analysis..."
rm -rf "$APP_SOURCE"
apktool d "$APK_IN" -o "$APP_SOURCE" -f

echo "[*] Scanning for obfuscated libraries..."
TARGET_LIBS=()
while IFS= read -r -d '' lib; do
    if nm -D "$lib" 2>/dev/null | grep -qE 'obfs_check1_start|obfs_check1_finish'; then
        echo "[+] Found target: $(basename "$lib")"
        TARGET_LIBS+=("$lib")
    fi
done < <(find "$APP_SOURCE/lib/arm64-v8a" -name "*.so" -print0)

if [ ${#TARGET_LIBS[@]} -gt 0 ]; then
    TEMP_PROJ="/tmp/ghidra_proj_$(date +%s)"
    mkdir -p "$TEMP_PROJ"
    ghidra-analyzeHeadless "$TEMP_PROJ" Temp -import "${TARGET_LIBS[@]}" -postScript "$GHIDRA_SCRIPT" -deleteProject
    rm -rf "$TEMP_PROJ"
fi

echo "[*] Step 4: Applying ReVanced patches..."
java -jar "$CLI_JAR" patch \
     --patches "$PATCHES_RVP" \
     --out "$BASE_PATCHED" \
     "$APK_IN"

echo "[*] Step 5: Finalizing APK..."
cd "$APP_SOURCE"
zip -ur "$BASE_PATCHED" lib/arm64-v8a/*.so
cd "$GHIDRA_DIR"

"$ZIPALIGN" -f -v 4 "$BASE_PATCHED" "$ALIGNED_APK"
"$APKSIGNER" sign --ks "$KEYSTORE" --ks-pass pass:password --out "$APK_OUT" "$ALIGNED_APK"

echo "[*] Step 6: Cleaning up..."
rm -rf "$APP_SOURCE"
rm -f "$BASE_PATCHED"
rm -f "$ALIGNED_APK"
rm -f "$GHIDRA_DIR"/*.idsig
rm -f "$GHIDRA_DIR"/*.keystore.idsig
rm -rf "$GHIDRA_DIR"/*-temporary-files
rm -f "$GHIDRA_DIR/base_patched.keystore"

cd "$ROOT_DIR"
"$GRADLEW" clean

echo "[+++] SUCCESS! Created: $APK_OUT"
