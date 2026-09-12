# Per-architecture afl-qemu-trace

`coverage_fuzz` uses AFL++'s qemu-mode, whose fork server removes process startup from every
execution. That is the difference between fuzzing a cross-architecture binary at ~40 exec/s
and at ~2,000.

The catch is that `afl-qemu-trace` emulates exactly one guest, chosen at build time, and AFL++
installs every build under the same name. `file afl-qemu-trace` does not tell you which guest
it targets -- it is an emulator, so it always reads as a host binary. Ask qemu instead:

    $ afl-qemu-trace --version
    qemu-aarch64 version 5.2.50

lykos resolves one per target: an arch-suffixed neighbour (`afl-qemu-trace-arm`) or an explicit
`LYKOS_AFL_QEMU_ARM=/path/to/binary`, and it verifies the guest from that banner before using
it -- naming a file `-arm` does not make it emulate ARM, and an unverified one aborts at the
fork-server handshake.

    ./build.sh arm          # -> /usr/local/bin/afl-qemu-trace-arm
    ./build.sh x86_64       # -> /usr/local/bin/afl-qemu-trace-x86-64
    ./build.sh aarch64

Measured here on jhead, 32-bit ARM: 1,965 exec/s and a confirmed crash in 60 seconds, against
~39-55 exec/s for the black-box qemu path that was previously the only option.

When no matching emulator exists the stage says so and names the build command rather than
running a campaign that cannot work.
