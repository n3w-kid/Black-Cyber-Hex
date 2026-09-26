# syntax=docker/dockerfile:1.7

FROM golang:bookworm AS go-tools
ENV CGO_ENABLED=0 GOBIN=/out
RUN mkdir -p /out && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

FROM debian:bookworm-slim AS source-tools
RUN apt-get update && apt-get install -y --no-install-recommends git build-essential ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git clone --depth=1 https://github.com/blechschmidt/massdns.git && make -C massdns && \
    git clone --depth=1 https://github.com/sqlmapproject/sqlmap.git && \
    git clone --depth=1 https://github.com/sullo/nikto.git && \
    rm -rf sqlmap/.git nikto/.git

FROM python:3.13-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH="/opt/sqlmap:/opt/nikto/program:$PATH"
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap masscan perl libnet-ssleay-perl ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*
COPY --from=go-tools /out/httpx /usr/local/bin/pd-httpx
COPY --from=go-tools /out/katana /usr/local/bin/katana
COPY --from=go-tools /out/nuclei /usr/local/bin/nuclei
COPY --from=source-tools /src/massdns/bin/massdns /usr/local/bin/massdns
COPY --from=source-tools /src/sqlmap /opt/sqlmap
COPY --from=source-tools /src/nikto /opt/nikto
RUN printf '#!/bin/sh\nexec python3 /opt/sqlmap/sqlmap.py "$@"\n' > /usr/local/bin/sqlmap && \
    printf '#!/bin/sh\nexec perl /opt/nikto/program/nikto.pl "$@"\n' > /usr/local/bin/nikto && \
    chmod +x /usr/local/bin/sqlmap /usr/local/bin/nikto /usr/local/bin/massdns /usr/local/bin/pd-httpx /usr/local/bin/katana /usr/local/bin/nuclei
WORKDIR /app
COPY . /app
RUN chmod +x /app/bch.py && mkdir -p /app/reports
ENTRYPOINT ["/usr/bin/tini","--","python3","/app/bch.py"]
CMD []
