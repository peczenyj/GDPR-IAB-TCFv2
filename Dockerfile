# --- Stage 1: Build & Install ---
FROM perl:5.40-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    make \
    gcc \
    libc6-dev \
    libssl-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Install cpanminus
RUN cpanm --notest App::cpanminus

WORKDIR /build

# Copy the entire project
COPY . .

# Install dependencies and the module itself
# We include JSON::XS for performance and Net::SSLeay for SSL support
RUN cpanm --notest --installdeps . \
    && cpanm --notest JSON::XS Net::SSLeay IO::Socket::SSL DateTimeX::TO_JSON

# Install the module to /usr/local
RUN perl Makefile.PL \
    && make \
    && make install

# --- Stage 2: Runtime ---
FROM perl:5.40-slim

# Install runtime SSL libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy installed files from builder
# We copy /usr/local completely to ensure all libs and binaries are present
COPY --from=builder /usr/local /usr/local

# Set environment variables
ENV PERL5LIB=/usr/local/lib/perl5/site_perl/5.40.0:/usr/local/share/perl5/site_perl/5.40.0
ENV PATH="/usr/local/bin:${PATH}"

# Smoke test (iabtcfv2 --help exits with 1)
RUN iabtcfv2 --help; if [ $? -ne 1 ]; then exit 1; else exit 0; fi

ENTRYPOINT ["iabtcfv2"]
CMD ["--help"]
