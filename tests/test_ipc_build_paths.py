"""IPC channel keys must not include compiler-embedded build-tree paths.

Every library of one source build embeds the same `__FILE__` strings and the source root they sit
under. Read as channel names, FreeRDP's libwinpr / libfreerdp-client "shared a socket channel"
named after a header file, and whole_system then tried to connect to it as a TCP port."""
from lykos.analyze.link.ipc import _scan_keys


def test_build_tree_paths_are_not_channel_keys():
    blob = (b"\0/tmp/lykos-upload-x/bundle/freerdp-3.20.0\0"
            b"/tmp/lykos-upload-x/bundle/freerdp-3.20.0/winpr/include/winpr/stream.h\0"
            b"/tmp/lykos-upload-x/bundle/freerdp-3.20.0/libfreerdp/codec/planar.c\0"
            b"/run/myservice/control.sock\0/var/run/app.pid\0")
    keys = _scan_keys(blob)
    assert "/run/myservice/control.sock" in keys
    assert "/var/run/app.pid" in keys
    assert not any("freerdp-3.20.0" in k for k in keys), keys


def test_a_channel_path_with_no_source_file_under_it_is_kept():
    keys = _scan_keys(b"\0/tmp/app.sock\0/dev/shm/ring0\0")
    assert keys == {"/tmp/app.sock", "/dev/shm/ring0"}
