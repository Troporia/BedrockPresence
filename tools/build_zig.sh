#!/usr/bin/env bash
# Cross-build bedrock_presence.dll + injector for Windows x64 from Linux/macOS
# with zig (mingw target). Output: dist/.
#   ZIG="zig" tools/build_zig.sh          (default: zig on PATH)
#   ZIG="python -m ziglang" tools/build_zig.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ZIG="${ZIG:-zig}"
OUT="$ROOT/build/zig"
DEPS="$OUT/deps"
DIST="$ROOT/dist"
TARGET="x86_64-windows-gnu"
mkdir -p "$OUT/obj" "$DEPS" "$DIST"

fetch() { # name url tag
  [ -d "$DEPS/$1" ] || git clone -q --depth 1 -b "$3" "$2" "$DEPS/$1"
}
fetch minhook https://github.com/TsudaKageyu/minhook.git v1.3.4
fetch miniz https://github.com/richgel999/miniz.git 3.0.2
if [ ! -d "$DEPS/json" ]; then
  curl -sSL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz | tar xJ -C "$DEPS"
fi
mkdir -p "$DEPS/stub"
echo '#define MINIZ_EXPORT' > "$DEPS/stub/miniz_export.h"

INC=(-I"$DEPS/minhook/include" -I"$DEPS/json/include" -I"$DEPS/miniz" -I"$DEPS/stub")
OBJS=()
for f in "$DEPS"/minhook/src/{buffer,hook,trampoline}.c "$DEPS"/minhook/src/hde/hde64.c \
         "$DEPS"/miniz/{miniz,miniz_tinfl,miniz_tdef,miniz_zip}.c; do
  o="$OUT/obj/$(basename "$f").o"
  $ZIG cc -target $TARGET -O2 -c "${INC[@]}" -o "$o" "$f"
  OBJS+=("$o")
done
for f in "$ROOT"/src/payload/*.cpp; do
  o="$OUT/obj/$(basename "$f").o"
  $ZIG c++ -target $TARGET -std=c++20 -O2 -g0 -c -DWIN32_LEAN_AND_MEAN -DNOMINMAX "${INC[@]}" -o "$o" "$f"
  OBJS+=("$o")
done

$ZIG c++ -target $TARGET -shared -O2 -s -o "$DIST/bedrock_presence.dll" "${OBJS[@]}" \
  -lws2_32 -lsecur32 -lcrypt32 -lbcrypt -lpsapi -luser32
$ZIG c++ -target $TARGET -std=c++20 -O2 -s -municode -o "$DIST/bedrock_presence_injector.exe" \
  "$ROOT/src/injector/main.cpp" -ladvapi32 -lkernel32
cp "$ROOT/config.example.json" "$ROOT/examples/presence_server.py" "$DIST/"
rm -f "$DIST"/*.pdb "$DIST"/*.lib
ls -la "$DIST"
