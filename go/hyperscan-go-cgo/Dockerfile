# syntax=docker/dockerfile:1
# Build context: repository root (pass with: docker buildx build --platform linux/amd64 -f go/hyperscan-go-cgo/Dockerfile <repo-root>)
#
# Stages:
#   1. Build + install libhs (hs + hs_runtime targets only) from the repo source.
#   2. Run Go unit tests and benchmarks against the installed library.
#
# We build ONLY the hs and hs_runtime CMake targets to avoid compiling the
# optional tools, unit tests, and chimera library. We pin -march=x86-64-v2
# (rather than the upstream default -march=native) so the image is portable
# across CPU generations within the x86-64-v2 baseline.

FROM --platform=linux/amd64 golang:1.26-bookworm

# Install build dependencies for Hyperscan and CGO.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    g++ \
    libboost-dev \
    ragel \
    libssl-dev \
    pkg-config \
  && rm -rf /var/lib/apt/lists/*

# Copy the entire repository into the image.
COPY . /src

# Configure Hyperscan with a portable baseline ISA and static libraries.
# We set both C and C++ flags to -march=x86-64-v2 for reproducibility.
RUN cmake \
      -S /src \
      -B /build \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/usr/local \
      -DBUILD_SHARED_LIBS=OFF \
      "-DCMAKE_C_FLAGS=-march=x86-64-v2" \
      "-DCMAKE_CXX_FLAGS=-march=x86-64-v2"

# Build only the library targets (hs = main library, hs_runtime = runtime-only
# library used for serialised database loading). Avoids compiling hsdump,
# unit tests, and chimera, keeping build time reasonable.
RUN cmake --build /build -j "$(nproc)" --target hs hs_runtime

# Install headers and libraries to /usr/local and refresh the linker cache.
RUN cmake --install /build && ldconfig

# Sanity check: verify pkg-config can find libhs 5.4.2.
RUN pkg-config --modversion libhs

# Switch to the Go package directory for all subsequent operations.
WORKDIR /src/go/hyperscan-go-cgo

# CGO_ENABLED=1 is required (the package uses cgo).
# The package's cgo directive (#cgo pkg-config: --static libhs) handles pulling
# libhs's private deps (-lstdc++ -lm -lcrypto); no PKG_CONFIG env var is needed.
ENV CGO_ENABLED=1

# Default command: run the full test suite (verbose) followed by benchmarks.
# Use -count=1 to bypass the test cache.
CMD go test -count=1 -v ./... && \
    go test -count=1 -run='^$' -bench=. -benchmem ./...
