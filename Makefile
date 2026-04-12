.PHONY: build build-cli build-sshfs run-sshfs install clean

IMAGE = mounter-sshfs-rs
CONTAINER = mounter

# Build everything
build: build-cli build-sshfs

# Build the macOS CLI
build-cli:
	cd mounter && cargo build --release

# Build the Docker image (sshfs-rs + samba)
build-sshfs:
	docker build -f Dockerfile.sshfs-rs -t $(IMAGE) .

# Start the sshfs container (privileged for FUSE, auto-restart)
run-sshfs: build-sshfs
	-docker rm -f $(CONTAINER) 2>/dev/null
	docker run -d --name $(CONTAINER) --privileged --restart unless-stopped $(IMAGE)
	@echo "Container '$(CONTAINER)' running."

# Install the CLI to /usr/local/bin
install: build
	cp mounter/target/release/mounter /usr/local/bin/

clean:
	-docker rm -f $(CONTAINER) 2>/dev/null
	-docker rmi $(IMAGE) 2>/dev/null
	cd mounter && cargo clean
	cd sshfs-rs && cargo clean
