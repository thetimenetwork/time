# Build ONLY the allowlisted release/context, never the production repository.
# No mutable image defaults. tools/build.mjs validates all three digest pins.
ARG RUST_IMAGE
ARG GO_IMAGE
ARG RUNTIME_IMAGE
FROM ${RUST_IMAGE} AS rustbuild
ARG RUST_IMAGE
RUN printf '%s\n' "$RUST_IMAGE" | grep -E '^[-a-zA-Z0-9./:_]+@sha256:[a-f0-9]{64}$'
WORKDIR /source
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
COPY spec/action-v1.json ./spec/action-v1.json
COPY v2 ./v2
COPY v4 ./v4
COPY pos ./pos
COPY treasury ./treasury
COPY bitcoin-bridge ./bitcoin-bridge
COPY history ./history
COPY registration ./registration
ENV CARGO_BUILD_JOBS=1
RUN test "$(rustc --version | cut -d ' ' -f2)" = 1.99.1 && rustup component add clippy rustfmt && cargo fetch --manifest-path v4/Cargo.toml --locked && cargo fetch --manifest-path pos/Cargo.toml --locked && cargo fetch --manifest-path history/Cargo.toml --locked && cargo fetch --manifest-path registration/Cargo.toml --locked && cargo fetch --manifest-path bitcoin-bridge/Cargo.toml --locked && cargo fetch --manifest-path treasury/Cargo.toml --locked && cargo build --manifest-path v4/Cargo.toml --release --locked --bin time-node-v4

FROM ${GO_IMAGE} AS gobuild
ARG GO_IMAGE
RUN printf '%s\n' "$GO_IMAGE" | grep -E '^[-a-zA-Z0-9./:_]+@sha256:[a-f0-9]{64}$'
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=1
WORKDIR /bootstrap
RUN test "$(go version | cut -d ' ' -f3)" = go1.27.3 && go mod init bootstrap && go mod download -json github.com/cometbft/cometbft@v0.38.26 > /module.json && grep -F '"Sum": "h1:MIPYgOSvyyiN1jo3SZljKy4ZXqs896aQnj3pQFfUmaE="' /module.json && grep -F '"Hash": "94d77f9f51a72e2b7d832798859f6222f08028f8"' /module.json && mkdir /source && cp -a /go/pkg/mod/github.com/cometbft/cometbft@v0.38.26/. /source/ && chmod -R u+w /source
WORKDIR /source
COPY consensus/go.mod consensus/go.sum ./
RUN sha256sum go.mod go.sum > /locked.sha256 && go mod download && sha256sum --check /locked.sha256 && go mod verify && go build -mod=readonly -trimpath -buildvcs=false -ldflags '-s -w -X github.com/cometbft/cometbft/version.TMGitCommitHash=94d77f9f51a72e2b7d832798859f6222f08028f8-tc-dependencies-1' -o /out/cometbft ./cmd/cometbft && sha256sum --check /locked.sha256

FROM ${RUNTIME_IMAGE} AS runtime
ARG RUNTIME_IMAGE
RUN printf '%s\n' "$RUNTIME_IMAGE" | grep -E '^[-a-zA-Z0-9./:_]+@sha256:[a-f0-9]{64}$'
# Runtime image must supply Node >=26, glibc, CA roots, and a POSIX shell.
RUN test "$(node -p 'Number(process.versions.node.split(".")[0])>=26')" = true && groupadd -g 10001 time && useradd -u 10001 -g 10001 -d /data -M time && mkdir -p /data/ledger /data/comet && chown -R 10001:10001 /data
COPY --from=rustbuild /source/v4/target/release/time-node-v4 /usr/local/bin/time-node-v4
COPY --from=gobuild /out/cometbft /usr/local/bin/cometbft
COPY deploy /opt/time/deploy
USER 10001:10001
WORKDIR /data
EXPOSE 26656
STOPSIGNAL SIGTERM
ENTRYPOINT ["node","/opt/time/deploy/operator.mjs"]
CMD ["help"]
