# --- Stage 1: Build & Install ---
FROM perl:5.42-slim AS builder

# Build dependencies (compiler + headers for any XS deps that recommends pulls
# in -- JSON::XS, Net::SSLeay, IO::Socket::SSL, etc.).
RUN apt-get update && apt-get install -y --no-install-recommends \
    make \
    gcc \
    libc6-dev \
    libssl-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN cpanm --notest App::cpanminus

WORKDIR /build

COPY . .

# Install runtime + recommends in one shot.
#   --installdeps .       : honors PREREQ_PM
#   --with-recommends     : pulls JSON::PP, Time::Piece, HTTP::Tiny, JSON,
#                           JSON::XS, DateTimeX::TO_JSON from the META
#                           recommends block. Net::SSLeay / IO::Socket::SSL
#                           come in transitively through HTTP::Tiny for HTTPS.
#   --with-test-recommends: include test-side recommends so a CI rebuild of
#                           this image can reproduce the full test environment.
RUN cpanm --notest --with-recommends --with-test-recommends --installdeps .

RUN perl Makefile.PL \
    && make \
    && make install

# --- Stage 2: Runtime ---
FROM perl:5.42-slim

# Runtime SSL libs only; build-time toolchain is left in stage 1.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Perl modules + the iabtcfv2 binary.
COPY --from=builder /usr/local /usr/local

# Discover the perl version dynamically rather than hard-coding 5.42.0; the
# base image bumps will then only require touching the FROM line above.
ENV PATH="/usr/local/bin:${PATH}"

# Smoke test: --version exits 0 cleanly and confirms the dist + the iabtcfv2
# CLI loaded together.
RUN iabtcfv2 --version

ENTRYPOINT ["iabtcfv2"]
CMD ["--help"]
