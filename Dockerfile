# a2pwn — autonomous, evidence-grounded web-pentest orchestrator.
#
# Batteries included: the a2pwn package + all Python deps, the burpwn sandbox/intercepting proxy,
# and (via claude-agent-sdk) a bundled Claude Code CLI. The sub-agents drive ALL traffic through
# burpwn's rootless user+network namespace, so the container must be allowed to create nested
# namespaces and program nftables — run it with `--privileged` (simplest) or the equivalent caps.
#
#   # subscription backend (mount your Claude Code login):
#   docker run --rm -it --privileged -v "$HOME/.claude:/root/.claude" \
#     own2pwnfr/a2pwn run -t https://ginandjuice.shop -o "find and prove web vulns" --yes
#
#   # API backend instead (no subscription):
#   docker run --rm -it --privileged -e ANTHROPIC_API_KEY=sk-... \
#     own2pwnfr/a2pwn run -t https://ginandjuice.shop -o "..." \
#     --executor-model anthropic:claude-sonnet-4-5 --verifier-model anthropic:claude-opus-4-5 --yes
#
#   # persist reports/HAR:  -v "$PWD/out:/root/.local/share/a2pwn"

# Debian trixie (glibc >= 2.39) — the prebuilt burpwn release binary is linked against GLIBC_2.39,
# which bookworm's 2.36 does not provide.
FROM python:3.12-slim-trixie

# System deps for the burpwn sandbox: bubblewrap (fs/pid isolation), nftables + iptables (the
# transparent-redirect ruleset), iproute2 (ip), uidmap (rootless subuid mapping), TLS roots, curl.
RUN apt-get update && apt-get install -y --no-install-recommends \
        bubblewrap nftables iptables iproute2 uidmap ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# burpwn — the transparent intercepting proxy + rootless sandbox (prebuilt release binary).
ARG BURPWN_VERSION=latest
RUN set -eux; \
    arch="$(uname -m)"; \
    case "$arch" in \
        x86_64|amd64) t=x86_64-unknown-linux-gnu ;; \
        aarch64|arm64) t=aarch64-unknown-linux-gnu ;; \
        *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    if [ "$BURPWN_VERSION" = latest ]; then \
        url="https://github.com/own2pwn-fr/burpwn/releases/latest/download/burpwn-$t.tar.gz"; \
    else \
        url="https://github.com/own2pwn-fr/burpwn/releases/download/$BURPWN_VERSION/burpwn-$t.tar.gz"; \
    fi; \
    curl -fsSL "$url" -o /tmp/b.tar.gz; \
    tar -xzf /tmp/b.tar.gz -C /tmp; \
    install -m0755 "/tmp/burpwn-$t/burpwn" /usr/local/bin/burpwn; \
    rm -rf /tmp/b.tar.gz "/tmp/burpwn-$t"; \
    burpwn --version

# uv for a fast, reproducible install.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# a2pwn itself (the wheel force-includes the seed skill library under a2pwn/_skills).
WORKDIR /opt/a2pwn
COPY pyproject.toml README.md LICENSE CHANGELOG.md ./
COPY src ./src
COPY skills ./skills
RUN uv pip install --system --no-cache .

# Rootless subuid/subgid ranges so burpwn can build its user namespace as root-in-container.
RUN echo "root:100000:65536" > /etc/subuid && echo "root:100000:65536" > /etc/subgid

# Reports + HAR land here (mount it to keep them).
ENV XDG_DATA_HOME=/root/.local/share
WORKDIR /work
ENTRYPOINT ["a2pwn"]
CMD ["--help"]
