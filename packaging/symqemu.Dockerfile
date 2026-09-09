FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates build-essential cmake ninja-build pkg-config \
    python3 python3-pip python3-venv python3-tomli python3-setuptools \
    libglib2.0-dev libpixman-1-dev libz3-dev z3 llvm-14-dev llvm-14-tools clang flex bison \
 && rm -rf /var/lib/apt/lists/*
# clone WITHOUT full submodule recursion (QEMU's ROM submodules are unneeded for user-mode
# and fragile); init only the SymCC runtime submodule.
RUN git clone --depth 1 https://github.com/eurecom-s3/symqemu.git /symqemu
WORKDIR /symqemu
RUN git submodule update --init --recursive subprojects/symcc-rt
RUN mkdir build && cd build && ../configure \
      --audio-drv-list= --disable-sdl --disable-gtk --disable-vte \
      --disable-opengl --disable-virglrenderer --disable-werror \
      --target-list=x86_64-linux-user \
 && make -j"$(nproc)"
RUN test -f /symqemu/build/qemu-x86_64 && echo "SYMQEMU BUILT OK"
