"""Build-dependency PRE-FLIGHT: what a source project declares it needs, and whether this host
has it -- so an operator stages the missing pieces BEFORE carrying the box offline.

The offline build sandbox cannot fetch anything (that is the whole point: it is air-gapped and
network-less). So when a project fails to build there, the loss is not partial -- the entire
binary/dynamic capability of the tool does not run for that target, and the operator finds out
only after a long failed run. This module turns that silent, after-the-fact failure into a
checklist computed up front: it reads the project's OWN build declarations (CMake
`find_package`/`pkg_check_modules`/`find_library`, autotools `AC_CHECK_LIB`/`PKG_CHECK_MODULES`,
pkg-config `.pc` Requires, and well-known library `#include`s) and checks each against what is
actually on this host, using the compiler's and pkg-config's own search -- not a guess.

Offline-honest by construction: it never claims it can obtain a dependency, only reports which
ones to stage. And it holds the platform's precision rule -- a requirement is reported MISSING
only when the host's own tools say it is absent; anything we cannot check for sure is reported
as unknown, never as a false alarm.
"""
from __future__ import annotations

import functools
import os
import re
import shutil
import subprocess
from pathlib import Path

# Directories under a source tree that are not the project's own build inputs -- vendored copies,
# examples and tests often #include third-party headers the project itself does not depend on.
_SKIP_SEG = {"examples", "example", "demo", "demos", "test", "tests", "third_party", "3rdparty",
             "vendor", "node_modules", ".git", "_lykos_build", "build"}
_SRC_EXT = {".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hpp", ".hh", ".hxx"}
_MAX_SCAN_FILES = 4000

# Headers that are the C/C++ standard library or POSIX -- present wherever a compiler is, so an
# include of one is never a third-party dependency. Only used to prune the include scan.
_STDLIB_HEADERS = {
    "stdio.h", "stdlib.h", "string.h", "strings.h", "stdint.h", "stddef.h", "stdbool.h",
    "stdarg.h", "ctype.h", "errno.h", "math.h", "limits.h", "float.h", "assert.h", "time.h",
    "signal.h", "setjmp.h", "locale.h", "wchar.h", "wctype.h", "inttypes.h", "iso646.h",
    "complex.h", "fenv.h", "tgmath.h", "stdalign.h", "stdatomic.h", "stdnoreturn.h", "threads.h",
    "unistd.h", "fcntl.h", "dirent.h", "poll.h", "sched.h", "pthread.h", "semaphore.h",
    "sys/types.h", "sys/stat.h", "sys/socket.h", "sys/time.h", "sys/wait.h", "sys/mman.h",
    "sys/ioctl.h", "sys/uio.h", "sys/un.h", "sys/select.h", "sys/resource.h", "sys/file.h",
    "sys/param.h", "sys/utsname.h", "sys/syscall.h", "sys/epoll.h", "sys/eventfd.h",
    "netinet/in.h", "netinet/tcp.h", "arpa/inet.h", "netdb.h", "ifaddrs.h", "net/if.h",
    "iostream", "vector", "string", "map", "set", "unordered_map", "unordered_set", "memory",
    "algorithm", "functional", "utility", "stdexcept", "cstdio", "cstdlib", "cstring", "cstdint",
    "cmath", "cassert", "cctype", "cerrno", "climits", "cstddef", "cstdarg", "ctime", "cwchar",
    "array", "deque", "list", "queue", "stack", "tuple", "optional", "variant", "any", "fstream",
    "sstream", "iomanip", "iterator", "numeric", "limits", "type_traits", "chrono", "thread",
    "mutex", "atomic", "condition_variable", "future", "regex", "random", "bitset", "complex",
    "initializer_list", "typeinfo", "new", "exception",
}

# Known library HEADERS -> the pkg-config-ish TOKEN naming the dependency. Drives the include
# scan: an angle-include of one of these, unresolved on the host, is a confident MISSING dep.
# (The build-system parsers below find deps generically; this curated map only adds the headers
#  a project pulls in without declaring them to CMake/autotools, kept to well-known libraries so
#  the include scan never cries wolf on a project-internal or generated header.)
_HEADER_TOKEN = {
    "openssl/ssl.h": "openssl", "openssl/crypto.h": "openssl", "openssl/evp.h": "openssl",
    "zlib.h": "zlib", "zstd.h": "libzstd", "lzma.h": "liblzma", "bzlib.h": "bzip2",
    "lz4.h": "liblz4", "brotli/decode.h": "libbrotlidec", "snappy.h": "libsnappy",
    "png.h": "libpng", "jpeglib.h": "libjpeg", "gif_lib.h": "giflib", "tiff.h": "libtiff-4",
    "tiffio.h": "libtiff-4", "webp/decode.h": "libwebp", "jerror.h": "libjpeg",
    "curl/curl.h": "libcurl", "sqlite3.h": "sqlite3", "mysql/mysql.h": "mysqlclient",
    "libpq-fe.h": "libpq", "expat.h": "expat", "libxml/parser.h": "libxml-2.0",
    "libxml/xmlreader.h": "libxml-2.0", "yaml.h": "yaml-0.1", "json-c/json.h": "json-c",
    "jansson.h": "jansson", "cjson/cJSON.h": "libcjson",
    "pcre2.h": "libpcre2-8", "pcre.h": "libpcre", "ncurses.h": "ncurses",
    "ncurses/ncurses.h": "ncurses", "readline/readline.h": "readline", "editline/readline.h": "libedit",
    "ffi.h": "libffi", "glib.h": "glib-2.0", "glib-2.0/glib.h": "glib-2.0",
    "gmp.h": "gmp", "mpfr.h": "mpfr",
    "ssh2.h": "libssh2", "libssh/libssh.h": "libssh", "libusb-1.0/libusb.h": "libusb-1.0",
    "dbus/dbus.h": "dbus-1", "systemd/sd-bus.h": "libsystemd", "cap-ng.h": "libcap-ng",
    "sys/capability.h": "libcap", "selinux/selinux.h": "libselinux", "pcap.h": "libpcap",
    "event2/event.h": "libevent", "event.h": "libevent", "uv.h": "libuv", "ev.h": "libev",
    "gnutls/gnutls.h": "gnutls", "nettle/aes.h": "nettle", "sodium.h": "libsodium",
    "krb5.h": "krb5", "ldap.h": "ldap", "sasl/sasl.h": "libsasl2",
    "freetype/freetype.h": "freetype2", "ft2build.h": "freetype2", "fontconfig/fontconfig.h": "fontconfig",
    "cairo.h": "cairo", "cairo/cairo.h": "cairo", "pango/pango.h": "pango-1.0",
    "gtk/gtk.h": "gtk+-3.0", "gdk-pixbuf/gdk-pixbuf.h": "gdk-pixbuf-2.0", "X11/Xlib.h": "x11",
    "SDL2/SDL.h": "sdl2", "SDL/SDL.h": "sdl", "GL/gl.h": "gl", "vulkan/vulkan.h": "vulkan",
    "alsa/asoundlib.h": "alsa", "pulse/pulseaudio.h": "libpulse", "sndfile.h": "sndfile",
    "ogg/ogg.h": "ogg", "vorbis/codec.h": "vorbis", "FLAC/all.h": "flac",
    "protobuf-c/protobuf-c.h": "libprotobuf-c", "google/protobuf/message.h": "protobuf",
    "archive.h": "libarchive", "magic.h": "libmagic", "udev.h": "libudev",
}

# A dependency TOKEN -> how to get it on the two main offline-target families, as a hint only.
# The authoritative output is always the token itself (a pkg-config module / header / library
# name); these package names just save the operator a lookup. Unknown tokens simply carry no hint.
_PKG_HINT = {
    "openssl": ("libssl-dev", "openssl-devel"), "zlib": ("zlib1g-dev", "zlib-devel"),
    "libzstd": ("libzstd-dev", "libzstd-devel"), "liblzma": ("liblzma-dev", "xz-devel"),
    "bzip2": ("libbz2-dev", "bzip2-devel"), "liblz4": ("liblz4-dev", "lz4-devel"),
    "libbrotlidec": ("libbrotli-dev", "brotli-devel"), "libsnappy": ("libsnappy-dev", "snappy-devel"),
    "libpng": ("libpng-dev", "libpng-devel"), "libjpeg": ("libjpeg-dev", "libjpeg-turbo-devel"),
    "giflib": ("libgif-dev", "giflib-devel"), "libtiff-4": ("libtiff-dev", "libtiff-devel"),
    "libwebp": ("libwebp-dev", "libwebp-devel"),
    "libcurl": ("libcurl4-openssl-dev", "libcurl-devel"), "sqlite3": ("libsqlite3-dev", "sqlite-devel"),
    "mysqlclient": ("libmysqlclient-dev", "mysql-devel"), "libpq": ("libpq-dev", "libpq-devel"),
    "expat": ("libexpat1-dev", "expat-devel"), "libxml-2.0": ("libxml2-dev", "libxml2-devel"),
    "yaml-0.1": ("libyaml-dev", "libyaml-devel"), "json-c": ("libjson-c-dev", "json-c-devel"),
    "jansson": ("libjansson-dev", "jansson-devel"), "libcjson": ("libcjson-dev", "cjson-devel"),
    "libpcre2-8": ("libpcre2-dev", "pcre2-devel"), "libpcre": ("libpcre3-dev", "pcre-devel"),
    "ncurses": ("libncurses-dev", "ncurses-devel"), "readline": ("libreadline-dev", "readline-devel"),
    "libedit": ("libedit-dev", "libedit-devel"), "libffi": ("libffi-dev", "libffi-devel"),
    "glib-2.0": ("libglib2.0-dev", "glib2-devel"), "gmp": ("libgmp-dev", "gmp-devel"),
    "mpfr": ("libmpfr-dev", "mpfr-devel"), "libssh2": ("libssh2-1-dev", "libssh2-devel"),
    "libssh": ("libssh-dev", "libssh-devel"), "libusb-1.0": ("libusb-1.0-0-dev", "libusbx-devel"),
    "dbus-1": ("libdbus-1-dev", "dbus-devel"), "libsystemd": ("libsystemd-dev", "systemd-devel"),
    "libcap-ng": ("libcap-ng-dev", "libcap-ng-devel"), "libcap": ("libcap-dev", "libcap-devel"),
    "libselinux": ("libselinux1-dev", "libselinux-devel"), "libpcap": ("libpcap-dev", "libpcap-devel"),
    "libevent": ("libevent-dev", "libevent-devel"), "libuv": ("libuv1-dev", "libuv-devel"),
    "libev": ("libev-dev", "libev-devel"), "gnutls": ("libgnutls28-dev", "gnutls-devel"),
    "nettle": ("nettle-dev", "nettle-devel"), "libsodium": ("libsodium-dev", "libsodium-devel"),
    "krb5": ("libkrb5-dev", "krb5-devel"), "ldap": ("libldap2-dev", "openldap-devel"),
    "libsasl2": ("libsasl2-dev", "cyrus-sasl-devel"), "freetype2": ("libfreetype-dev", "freetype-devel"),
    "fontconfig": ("libfontconfig-dev", "fontconfig-devel"), "cairo": ("libcairo2-dev", "cairo-devel"),
    "pango-1.0": ("libpango1.0-dev", "pango-devel"), "gtk+-3.0": ("libgtk-3-dev", "gtk3-devel"),
    "gdk-pixbuf-2.0": ("libgdk-pixbuf-2.0-dev", "gdk-pixbuf2-devel"), "x11": ("libx11-dev", "libX11-devel"),
    "sdl2": ("libsdl2-dev", "SDL2-devel"), "sdl": ("libsdl1.2-dev", "SDL-devel"),
    "gl": ("libgl-dev", "mesa-libGL-devel"), "vulkan": ("libvulkan-dev", "vulkan-loader-devel"),
    "alsa": ("libasound2-dev", "alsa-lib-devel"), "libpulse": ("libpulse-dev", "pulseaudio-libs-devel"),
    "sndfile": ("libsndfile1-dev", "libsndfile-devel"), "ogg": ("libogg-dev", "libogg-devel"),
    "vorbis": ("libvorbis-dev", "libvorbis-devel"), "flac": ("libflac-dev", "flac-devel"),
    "libprotobuf-c": ("libprotobuf-c-dev", "protobuf-c-devel"), "protobuf": ("libprotobuf-dev", "protobuf-devel"),
    "libarchive": ("libarchive-dev", "libarchive-devel"), "libmagic": ("libmagic-dev", "file-devel"),
    "libudev": ("libudev-dev", "systemd-devel"),
}

# CMake find_package(<Name>) -> a concrete token we CAN check (header or pkg-config module). A
# find_package name we cannot map is reported, but with presence UNKNOWN rather than missing --
# CMake's own package search is not reproducible offline, so we never call such a one missing.
_CMAKE_PKG = {
    "openssl": ("header", "openssl/ssl.h", "openssl"), "zlib": ("header", "zlib.h", "zlib"),
    "zstd": ("header", "zstd.h", "libzstd"), "liblzma": ("header", "lzma.h", "liblzma"),
    "lzma": ("header", "lzma.h", "liblzma"), "bzip2": ("header", "bzlib.h", "bzip2"),
    "lz4": ("header", "lz4.h", "liblz4"), "png": ("header", "png.h", "libpng"),
    "jpeg": ("header", "jpeglib.h", "libjpeg"), "jpegturbo": ("header", "jpeglib.h", "libjpeg"),
    "tiff": ("header", "tiffio.h", "libtiff-4"), "webp": ("header", "webp/decode.h", "libwebp"),
    "giflib": ("header", "gif_lib.h", "giflib"), "curl": ("header", "curl/curl.h", "libcurl"),
    "sqlite3": ("header", "sqlite3.h", "sqlite3"), "expat": ("header", "expat.h", "expat"),
    "libxml2": ("header", "libxml/parser.h", "libxml-2.0"), "pcre2": ("header", "pcre2.h", "libpcre2-8"),
    "pcre": ("header", "pcre.h", "libpcre"), "freetype": ("pc", "freetype2", "freetype2"),
    "fontconfig": ("header", "fontconfig/fontconfig.h", "fontconfig"),
    "libssh2": ("header", "ssh2.h", "libssh2"), "libssh": ("header", "libssh/libssh.h", "libssh"),
    "libusb": ("header", "libusb-1.0/libusb.h", "libusb-1.0"), "gnutls": ("header", "gnutls/gnutls.h", "gnutls"),
    "sodium": ("header", "sodium.h", "libsodium"), "libevent": ("header", "event2/event.h", "libevent"),
    "libuv": ("header", "uv.h", "libuv"), "gmp": ("header", "gmp.h", "gmp"),
    "readline": ("header", "readline/readline.h", "readline"), "ncurses": ("header", "ncurses.h", "ncurses"),
    "curses": ("header", "ncurses.h", "ncurses"), "libarchive": ("header", "archive.h", "libarchive"),
    "libpq": ("header", "libpq-fe.h", "libpq"), "postgresql": ("header", "libpq-fe.h", "libpq"),
    "glib": ("pc", "glib-2.0", "glib-2.0"), "sdl2": ("pc", "sdl2", "sdl2"),
    "x11": ("header", "X11/Xlib.h", "x11"), "protobuf": ("header", "google/protobuf/message.h", "protobuf"),
    "jansson": ("header", "jansson.h", "jansson"), "yaml": ("header", "yaml.h", "yaml-0.1"),
    "libyaml": ("header", "yaml.h", "yaml-0.1"), "json-c": ("header", "json-c/json.h", "json-c"),
    "ffi": ("header", "ffi.h", "libffi"), "libffi": ("header", "ffi.h", "libffi"),
    # These CMake modules are satisfied by the toolchain/libc itself -- never a stageable dep.
    "threads": ("builtin", "pthread", None), "zlibstatic": ("header", "zlib.h", "zlib"),
    "dl": ("builtin", "dl", None), "m": ("builtin", "m", None),
}

SCHEMA = "lykos.dep-preflight/1"


# ---- host-capability probes (the compiler's / pkg-config's OWN search, not a guess) ----

def _cc():
    return shutil.which("gcc") or shutil.which("cc") or shutil.which("clang")


@functools.lru_cache(maxsize=1)
def _include_dirs() -> tuple:
    """The header search path a build on THIS host actually uses: the compiler's own `#include <>`
    dirs (authoritative) plus the standard and multiarch roots as a fallback when no compiler is
    present. Parsed once from `cc -E -v` and cached."""
    dirs: list = []
    cc = _cc()
    if cc:
        try:
            r = subprocess.run([cc, "-xc", "-E", "-v", "-"], input=b"",
                               capture_output=True, timeout=10)
            txt = (r.stderr or b"").decode("utf-8", "replace")
            grab = False
            for line in txt.splitlines():
                if "#include <...> search starts here" in line:
                    grab = True
                    continue
                if "End of search list" in line:
                    break
                if grab:
                    d = line.strip().split(" (")[0].strip()
                    if d:
                        dirs.append(d)
        except (OSError, subprocess.SubprocessError):
            pass
    for d in ("/usr/include", "/usr/local/include"):
        if d not in dirs:
            dirs.append(d)
    # Debian/Ubuntu multiarch: /usr/include/x86_64-linux-gnu and friends.
    try:
        for m in Path("/usr/include").glob("*-linux-gnu*"):
            if m.is_dir() and str(m) not in dirs:
                dirs.append(str(m))
    except OSError:
        pass
    return tuple(d for d in dirs if os.path.isdir(d))


def _header_present(hdr: str) -> bool:
    return any((Path(d) / hdr).exists() for d in _include_dirs())


@functools.lru_cache(maxsize=1)
def _have_pkgconfig() -> bool:
    return bool(shutil.which("pkg-config") or shutil.which("pkgconf"))


def _pkgconfig_present(mod: str):
    """True/False from pkg-config's own database, or None when pkg-config is not installed (we
    cannot know, so we do not guess -- precision over coverage)."""
    if not _have_pkgconfig():
        return None
    pc = shutil.which("pkg-config") or shutil.which("pkgconf")
    try:
        r = subprocess.run([pc, "--exists", mod], capture_output=True, timeout=8)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return None


def _library_present(name: str):
    """Whether `-l<name>` would link here, via the compiler's own `-print-file-name` (returns an
    absolute path when found, the bare name when not) with an ldconfig fallback. None when neither
    the compiler nor ldconfig can answer."""
    cc = _cc()
    if cc:
        for ext in (".so", ".a"):
            try:
                r = subprocess.run([cc, f"-print-file-name=lib{name}{ext}"],
                                   capture_output=True, timeout=8)
                out = (r.stdout or b"").decode("utf-8", "replace").strip()
            except (OSError, subprocess.SubprocessError):
                out = ""
            if out and out != f"lib{name}{ext}" and os.path.exists(out):
                return True
    ldc = shutil.which("ldconfig")
    if ldc:
        try:
            r = subprocess.run([ldc, "-p"], capture_output=True, timeout=8)
            txt = (r.stdout or b"").decode("utf-8", "replace")
            if re.search(rf"\blib{re.escape(name)}\.so\b", txt):
                return True
            return False
        except (OSError, subprocess.SubprocessError):
            return None
    return None if not cc else False


def _check_token(kind: str, token: str):
    """Presence of one dependency token, by its kind. Returns True / False / None (unknown)."""
    if kind == "builtin":
        return True                                       # libc/toolchain-provided (pthread, dl, m)
    if kind == "pkg-config":
        return _pkgconfig_present(token)
    if kind == "header":
        return True if _header_present(token) else False
    if kind == "library":
        return _library_present(token)
    return None


# ---- build-declaration parsers (read the project's OWN files) ----

def _read(p: Path, limit: int = 512 * 1024) -> str:
    try:
        return p.read_text("utf-8", "replace")[:limit]
    except OSError:
        return ""


def _strip_cmake_comments(txt: str) -> str:
    return "\n".join(line.split("#", 1)[0] for line in txt.splitlines())


def _parse_cmake(text: str) -> list:
    """(kind, name, token-or-None) deps declared in a CMakeLists.txt / *.cmake body."""
    out: list = []
    t = _strip_cmake_comments(text)
    for m in re.finditer(r"\bfind_package\s*\(\s*([A-Za-z0-9_+.\-]+)", t, re.I):
        name = m.group(1)
        if name.upper() in ("PKGCONFIG", "PKG_CONFIG"):
            continue
        out.append(("cmake-package", name, None))
    for m in re.finditer(r"\b(?:pkg_check_modules|pkg_search_module)\s*\(([^)]*)\)", t, re.I):
        body = m.group(1)
        toks = re.findall(r"[A-Za-z0-9_][A-Za-z0-9_.\-]*", body)
        # first token is the result-prefix variable; QUIET/REQUIRED/IMPORTED_TARGET are keywords.
        kw = {"QUIET", "REQUIRED", "IMPORTED_TARGET", "GLOBAL", "NO_CMAKE_PATH"}
        for tok in toks[1:]:
            if tok in kw or ">=" in tok or "<=" in tok:
                continue
            mod = re.split(r"[<>=]", tok)[0]
            if mod and mod[:1].isalpha() and not mod.isupper():   # a module name, not a version
                out.append(("pkg-config", mod, mod))
    for m in re.finditer(r"\bfind_library\s*\(\s*[A-Za-z0-9_]+\s+(?:NAMES\s+)?([^)]*)\)", t, re.I):
        for lib in re.findall(r"[A-Za-z0-9_][A-Za-z0-9_.\-]*", m.group(1)):
            if lib in ("NAMES", "PATHS", "REQUIRED", "HINTS", "PATH_SUFFIXES", "DOC", "NO_DEFAULT_PATH"):
                continue
            out.append(("library", re.sub(r"^lib", "", lib), re.sub(r"^lib", "", lib)))
            break
    for m in re.finditer(r"\bcheck_include_files?\s*\(\s*\"?([A-Za-z0-9_./+\-]+\.h[a-z]*)", t, re.I):
        out.append(("header", m.group(1), m.group(1)))
    return out


def _parse_autotools(text: str) -> list:
    """(kind, name, token) deps declared in configure.ac / configure.in / configure."""
    out: list = []
    for m in re.finditer(r"\bAC_CHECK_LIB\s*\(\s*\[?\s*([A-Za-z0-9_.\-]+)", text):
        out.append(("library", m.group(1), m.group(1)))
    for m in re.finditer(r"\bAC_(?:CHECK|SEARCH)_HEADERS?\s*\(\s*\[?\s*([A-Za-z0-9_./+ \-]+)", text):
        for hdr in re.findall(r"[A-Za-z0-9_./+\-]+\.h[a-z]*", m.group(1)):
            out.append(("header", hdr, hdr))
    for m in re.finditer(r"\bPKG_CHECK_MODULES?\s*\(\s*\[?[^,]*,\s*\[?([^\])]*)", text):
        for tok in re.findall(r"[A-Za-z0-9_][A-Za-z0-9_.\-]*", m.group(1)):
            mod = re.split(r"[<>=]", tok)[0]
            if mod and mod[:1].isalpha() and not mod.isupper():   # module name, not a version
                out.append(("pkg-config", mod, mod))
    return out


def _parse_pc(text: str) -> list:
    out: list = []
    for m in re.finditer(r"^\s*Requires(?:\.private)?\s*:\s*(.+)$", text, re.M):
        for tok in re.findall(r"[A-Za-z0-9_][A-Za-z0-9_.\-]*", m.group(1)):
            mod = re.split(r"[<>=]", tok)[0]
            out.append(("pkg-config", mod, mod))
    return out


_INC_RE = re.compile(r'^\s*#\s*include\s*<([^>]+)>', re.M)


def _scan_includes(root: Path) -> list:
    """Well-known library headers the project `#include`s but may not declare to its build system.
    Only headers in `_HEADER_TOKEN` are considered, so this never misclassifies a generated or
    project-internal header as a missing dependency."""
    seen: dict = {}
    n = 0
    for p in root.rglob("*"):
        if n >= _MAX_SCAN_FILES:
            break
        if not p.is_file() or p.suffix not in _SRC_EXT:
            continue
        if any(seg in _SKIP_SEG for seg in p.parts):
            continue
        n += 1
        for inc in _INC_RE.findall(_read(p, 128 * 1024)):
            inc = inc.strip()
            if inc in _STDLIB_HEADERS or inc not in _HEADER_TOKEN:
                continue
            seen.setdefault(inc, _HEADER_TOKEN[inc])
    return [("header", h, h) for h in sorted(seen)]


def _project_root(root: Path) -> Path:
    """Reuse source_project's wrapper-dir descent so we scan the same tree the builder builds."""
    try:
        from . import source_project
        return source_project._project_root(root)
    except Exception:                                     # noqa: BLE001
        return root


def _detect_build_system(root: Path):
    if (root / "CMakeLists.txt").exists() or (root / "compile_commands.json").exists():
        return "cmake"
    if (root / "configure").exists() or (root / "configure.ac").exists() \
            or (root / "configure.in").exists():
        return "autotools"
    if any((root / m).exists() for m in ("Makefile", "makefile", "GNUmakefile")):
        return "make"
    return "plain"


def _toolchain(system: str) -> dict:
    """Which build TOOLS this project needs and whether they are here -- a missing cmake is as
    fatal as a missing library, and just as stageable."""
    tc = {"cc": bool(_cc()),
          "c++": bool(shutil.which("g++") or shutil.which("c++") or shutil.which("clang++")),
          "make": bool(shutil.which("make")),
          "pkg-config": _have_pkgconfig()}
    if system == "cmake":
        tc["cmake"] = bool(shutil.which("cmake"))
    if system == "autotools":
        tc["autoconf"] = bool(shutil.which("autoconf"))
        tc["automake"] = bool(shutil.which("automake"))
    return tc


def _hint(token) -> dict | None:
    h = _PKG_HINT.get(token) if token else None
    return {"apt": h[0], "dnf": h[1]} if h else None


def scan_dependencies(root, *, scan_includes: bool = True) -> dict:
    """Pre-flight the source project at `root`: what it declares it needs vs. what this host has.

    Returns a dict (schema `lykos.dep-preflight/1`) with `build_system`, `toolchain` (tool ->
    present), `requirements` (every declared dep with `present` True/False/None and a package
    `hint`), `missing` (the stage-these subset: present is exactly False), `unknown` (declared but
    uncheckable here), and a `summary`. Deterministic and offline: it reads files and asks the
    host's own compiler/pkg-config/ldconfig; it fetches nothing.
    """
    root = _project_root(Path(root).resolve())
    system = _detect_build_system(root)

    raw: list = []                                        # (kind, name, token)
    if system == "cmake":
        for name in ("CMakeLists.txt",):
            raw += _parse_cmake(_read(root / name))
        cnt = 0
        for cm in root.rglob("*.cmake"):
            if cnt >= 200 or any(seg in _SKIP_SEG for seg in cm.parts):
                continue
            cnt += 1
            raw += _parse_cmake(_read(cm))
    if system == "autotools":
        for name in ("configure.ac", "configure.in", "configure"):
            if (root / name).exists():
                raw += _parse_autotools(_read(root / name, 2 * 1024 * 1024))
                break
    for cnt, pc in enumerate(root.rglob("*.pc")):
        if cnt >= 100 or any(seg in _SKIP_SEG for seg in pc.parts):
            continue
        raw += _parse_pc(_read(pc))
    if scan_includes:
        raw += _scan_includes(root)

    # Resolve each declared dep to a concrete check, dedup by (kind-after-mapping, name).
    reqs: dict = {}
    for kind, name, token in raw:
        if kind == "cmake-package":
            mapped = _CMAKE_PKG.get(name.lower())
            if mapped:
                ck, ctok, hinttok = mapped
                present = _check_token(ck, ctok)
                token_for_hint = hinttok
                detail = f"CMake find_package({name}) -> {ck} {ctok}"
            else:
                present = None                            # cannot reproduce CMake's search offline
                token_for_hint = None
                detail = f"CMake find_package({name}) -- presence unknown offline"
            key = ("cmake-package", name.lower())
            reqs.setdefault(key, {"kind": "cmake-package", "name": name, "present": present,
                                  "hint": _hint(token_for_hint), "detail": detail})
            continue
        key = (kind, name.lower())
        if key in reqs:
            continue
        present = _check_token(kind, token)
        htok = token if kind == "pkg-config" else _HEADER_TOKEN.get(name) if kind == "header" else None
        reqs[key] = {"kind": kind, "name": name, "present": present, "hint": _hint(htok),
                     "detail": {"header": "header", "library": "-l library",
                                "pkg-config": "pkg-config module"}.get(kind, kind)}

    requirements = sorted(reqs.values(), key=lambda r: (r["present"] is not False, r["kind"], r["name"]))
    missing = [r for r in requirements if r["present"] is False]
    unknown = [r for r in requirements if r["present"] is None]
    present_n = sum(1 for r in requirements if r["present"] is True)
    tc = _toolchain(system)
    tc_missing = sorted(k for k, v in tc.items() if v is False)

    return {
        "schema": SCHEMA,
        "root": str(root),
        "build_system": system,
        "toolchain": tc,
        "toolchain_missing": tc_missing,
        "requirements": requirements,
        "missing": missing,
        "unknown": unknown,
        "summary": {"declared": len(requirements), "present": present_n,
                    "missing": len(missing), "unknown": len(unknown),
                    "toolchain_missing": len(tc_missing)},
    }


def missing_tokens(pf: dict) -> list:
    """A flat, de-duplicated list of the stage-these labels from a pre-flight dict -- the one-line
    'bring these' summary the ledger/report/GUI show when a build produced no binaries."""
    out: list = []
    for t in sorted(pf.get("toolchain_missing") or []):
        out.append(t)
    for r in pf.get("missing") or []:
        label = r["name"]
        h = r.get("hint")
        if h:
            label += f" ({h['apt']})"
        if label not in out:
            out.append(label)
    return out


def format_report(pf: dict) -> str:
    """Human-readable pre-flight for the CLI, in the shape of `toolchain.report`."""
    L: list = [f"Build-dependency pre-flight: {pf['root']}",
               f"  build system: {pf['build_system']}"]
    tc = pf["toolchain"]
    L.append("  toolchain:    " + "  ".join(
        f"{'ok ' if v else 'MISS'} {k}" for k, v in tc.items()))
    s = pf["summary"]
    L.append(f"  declared deps: {s['declared']}  (present {s['present']}, "
             f"MISSING {s['missing']}, unknown {s['unknown']})")
    if pf["missing"]:
        L.append("\nMISSING -- stage these BEFORE going offline:")
        for r in pf["missing"]:
            h = r.get("hint")
            hint = f"   apt: {h['apt']}  |  dnf: {h['dnf']}" if h else ""
            L.append(f"  [{r['kind']}] {r['name']}{hint}")
    if pf["unknown"]:
        L.append("\nUNKNOWN -- declared, but this host cannot confirm (check manually):")
        for r in pf["unknown"]:
            L.append(f"  [{r['kind']}] {r['name']}  ({r['detail']})")
    present = [r for r in pf["requirements"] if r["present"] is True]
    if present:
        L.append("\nPresent on this host: " + ", ".join(r["name"] for r in present))
    if not pf["missing"] and not pf["toolchain_missing"]:
        L.append("\nAll declared dependencies this host can check are present. Build should "
                 "have what it needs.")
    return "\n".join(L)
