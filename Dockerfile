# Stage 1: Build sshfs from source
FROM alpine:3.21 AS builder
RUN apk add --no-cache git gcc musl-dev meson ninja pkgconf fuse3-dev glib-dev
RUN git clone --depth 1 https://github.com/libfuse/sshfs.git /src/sshfs
WORKDIR /src/sshfs
RUN meson setup builddir && meson compile -C builddir && strip builddir/sshfs

# Stage 2: Minimal runtime
FROM alpine:3.21
RUN apk add --no-cache \
        fuse3 glib openssh-client \
        samba-server samba-common-tools && \
    mkdir -p /root/.ssh /mnt /run/samba /etc/mounter
COPY --from=builder /src/sshfs/builddir/sshfs /usr/local/bin/sshfs
COPY entrypoint.sh /entrypoint.sh
COPY monitor.sh /monitor.sh
RUN chmod +x /entrypoint.sh /monitor.sh
ENTRYPOINT ["/entrypoint.sh"]
