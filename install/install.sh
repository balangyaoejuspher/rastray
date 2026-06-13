#!/usr/bin/env sh
set -eu

REPO="balangyaoejuspher/rastray"
BIN="rastray"

if [ -n "${RASTRAY_VERSION:-}" ]; then
    VERSION="${RASTRAY_VERSION#v}"
else
    VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep -m 1 '"tag_name":' \
        | sed -E 's/.*"v?([^"]+)".*/\1/')
fi

if [ -z "${VERSION}" ]; then
    echo "error: could not determine release version" >&2
    exit 1
fi

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "${OS}" in
    linux)
        case "${ARCH}" in
            x86_64|amd64) TARGET="x86_64-unknown-linux-gnu" ;;
            *) echo "error: unsupported linux arch '${ARCH}'" >&2; exit 1 ;;
        esac
        ;;
    darwin)
        case "${ARCH}" in
            x86_64) TARGET="x86_64-apple-darwin" ;;
            arm64|aarch64) TARGET="aarch64-apple-darwin" ;;
            *) echo "error: unsupported darwin arch '${ARCH}'" >&2; exit 1 ;;
        esac
        ;;
    *)
        echo "error: unsupported OS '${OS}' (use the .ps1 installer on Windows)" >&2
        exit 1
        ;;
esac

INSTALL_DIR="${RASTRAY_INSTALL_DIR:-${HOME}/.local/bin}"
ARCHIVE="${BIN}-v${VERSION}-${TARGET}.tar.gz"
URL="https://github.com/${REPO}/releases/download/v${VERSION}/${ARCHIVE}"

TMP=$(mktemp -d)
trap 'rm -rf "${TMP}"' EXIT

echo "Downloading ${URL}"
if ! curl -fL --proto '=https' --tlsv1.2 -o "${TMP}/${ARCHIVE}" "${URL}"; then
    echo "error: download failed" >&2
    exit 1
fi

echo "Verifying checksum"
if ! curl -fL --proto '=https' --tlsv1.2 -o "${TMP}/${ARCHIVE}.sha256" "${URL}.sha256"; then
    echo "error: checksum download failed" >&2
    exit 1
fi

EXPECTED=$(awk '{print $1}' "${TMP}/${ARCHIVE}.sha256")
if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL=$(sha256sum "${TMP}/${ARCHIVE}" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
    ACTUAL=$(shasum -a 256 "${TMP}/${ARCHIVE}" | awk '{print $1}')
else
    echo "warning: no sha256 tool found, skipping verification" >&2
    ACTUAL="${EXPECTED}"
fi

if [ "${EXPECTED}" != "${ACTUAL}" ]; then
    echo "error: checksum mismatch (expected ${EXPECTED}, got ${ACTUAL})" >&2
    exit 1
fi

tar -xzf "${TMP}/${ARCHIVE}" -C "${TMP}"
mkdir -p "${INSTALL_DIR}"
install -m 755 "${TMP}/${BIN}-v${VERSION}-${TARGET}/${BIN}" "${INSTALL_DIR}/${BIN}"

echo "Installed ${BIN} v${VERSION} to ${INSTALL_DIR}/${BIN}"

case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *)
        echo
        echo "Note: ${INSTALL_DIR} is not on your PATH. Add it with:"
        echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
        ;;
esac
