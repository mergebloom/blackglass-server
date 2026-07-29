#!/bin/sh
set -eu

version=0.20.2
target=x86_64-unknown-linux-musl
archive="cargo-deny-${version}-${target}.tar.gz"
expected_sha256=9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f
url="https://github.com/EmbarkStudios/cargo-deny/releases/download/${version}/${archive}"

if [ "$#" -ne 1 ]; then
  echo "usage: install-cargo-deny.sh /absolute/destination" >&2
  exit 2
fi

destination=$1
case "$destination" in
  /*) ;;
  *)
    echo "cargo-deny destination must be absolute" >&2
    exit 2
    ;;
esac

destination_directory=$(dirname -- "$destination")
if [ ! -d "$destination_directory" ] || [ -L "$destination_directory" ]; then
  echo "cargo-deny destination directory must be an existing real directory" >&2
  exit 2
fi
if [ -e "$destination" ] || [ -L "$destination" ]; then
  echo "refusing to overwrite cargo-deny destination" >&2
  exit 2
fi

temporary_root=${RUNNER_TEMP:-/tmp}
if [ ! -d "$temporary_root" ] || [ -L "$temporary_root" ]; then
  echo "cargo-deny temporary root must be an existing real directory" >&2
  exit 2
fi
work=$(mktemp -d "$temporary_root/blackglass-cargo-deny.XXXXXX")
cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT HUP INT TERM

download="$work/$archive"
extracted="$work/extracted"
mkdir "$extracted"
curl \
  --fail \
  --location \
  --max-filesize 6000000 \
  --proto '=https' \
  --retry 3 \
  --show-error \
  --silent \
  --tlsv1.2 \
  --output "$download" \
  "$url"
printf '%s  %s\n' "$expected_sha256" "$download" | sha256sum -c -

if tar -tzf "$download" | awk '
  /^\// || /(^|\/)\.\.($|\/)/ { unsafe = 1 }
  END { exit unsafe ? 0 : 1 }
'; then
  echo "cargo-deny archive contains an unsafe path" >&2
  exit 1
fi
tar -xzf "$download" -C "$extracted" --strip-components=1

candidate="$extracted/cargo-deny"
if [ ! -f "$candidate" ] || [ -L "$candidate" ]; then
  echo "cargo-deny archive did not contain the expected executable" >&2
  exit 1
fi
if [ "$(find "$extracted" -type f -name cargo-deny | wc -l | tr -d ' ')" -ne 1 ]; then
  echo "cargo-deny archive contained an ambiguous executable" >&2
  exit 1
fi
chmod 0555 "$candidate"
if [ "$("$candidate" --version)" != "cargo-deny $version" ]; then
  echo "cargo-deny executable reported an unexpected version" >&2
  exit 1
fi
install -m 0555 "$candidate" "$destination"
