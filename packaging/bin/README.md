# Vendored build helpers

`patchelf-static-x86_64` — a **statically linked** patchelf (from the PyPI `patchelf`
wheel, musllinux build). It is copied into an offline bundle at
`vendor/toolchain/.relink/patchelf` and used by `relink-bundle.sh` on the target to make the
bundled tools glibc-independent. It must be static: it runs *before* the bundle's own glibc is
in play, on a host whose glibc may be older than the bundle's. Regenerate with:

    pip download patchelf -d /tmp/pf --no-deps && (cd /tmp/pf && unzip -o *.whl)
    cp /tmp/pf/patchelf-*.data/scripts/patchelf packaging/bin/patchelf-static-x86_64
