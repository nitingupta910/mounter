# Stage 1: Build sshfs from source (latest from git)
FROM ubuntu:24.04 AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates gcc libc-dev \
        meson ninja-build pkg-config \
        libfuse3-dev libglib2.0-dev && \
    rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/libfuse/sshfs.git /src/sshfs
WORKDIR /src/sshfs
RUN meson setup builddir && meson compile -C builddir && \
    strip builddir/sshfs

# Stage 2: Minimal runtime — sshfs + samba
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
        fuse3 libfuse3-3 libglib2.0-0 openssh-client \
        samba && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /root/.ssh /mnt
COPY --from=builder /src/sshfs/builddir/sshfs /usr/local/bin/sshfs
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
