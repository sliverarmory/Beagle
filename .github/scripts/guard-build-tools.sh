#!/usr/bin/env bash
# Put native failure stubs before PATH while testing ordinary Cargo builds.
# Prints the guard directory for callers to prepend to PATH. The optional
# BEAGLE_LEGACY_TOOL_LOG records attempts even if a caller ignores the failure.
set -euo pipefail

guard_dir="${1:?usage: guard-build-tools.sh DIRECTORY}"
mkdir -p "$guard_dir"
guard_dir="$(cd "$guard_dir" && pwd)"
suffix=""
case "${RUNNER_OS:-$(uname -s)}" in
  Windows|MINGW*|MSYS*) suffix=".exe" ;;
esac

cat > "$guard_dir/guard.c" <<'C'
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    (void)argc;
    const char *log_path = getenv("BEAGLE_LEGACY_TOOL_LOG");
    if (log_path != NULL) {
        FILE *log = fopen(log_path, "a");
        if (log != NULL) {
            fprintf(log, "Unexpected legacy build tool: %s\n", argv[0]);
            fclose(log);
        }
    }
    fprintf(stderr, "Unexpected legacy build tool: %s\n"
            "Cargo builds must not invoke Python, pip, angreal, or Make.\n", argv[0]);
    return 97;
}
C

"${CC:-gcc}" "$guard_dir/guard.c" -o "$guard_dir/guard$suffix"
for name in python python3 python3.11 python3.12 python3.13 python3.14 python3.15 \
            pip pip3 angreal make gmake mingw32-make; do
  cp "$guard_dir/guard$suffix" "$guard_dir/$name$suffix"
done

if [[ "$suffix" == .exe ]]; then
  cygpath -m "$guard_dir"
else
  printf '%s\n' "$guard_dir"
fi
