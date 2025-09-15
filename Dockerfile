FROM docker.io/ubuntu:25.04 AS build

WORKDIR /app

RUN apt-get update && \
    apt-get install -y vim gcc make clang libbpf-dev curl clang-format libcurl4-openssl-dev build-essential libelf-dev && \
    rm -rf /var/lib/apt/lists/*

COPY . .

RUN make && strip bin/rootisnaked

FROM docker.io/debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libbpf1 libelf1 zlib1g libcurl4 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/bin/rootisnaked /usr/local/bin/rootisnaked
COPY --from=build /app/build/rootisnaked.bpf.o /usr/local/share/rootisnaked/rootisnaked.bpf.o

ENTRYPOINT ["/usr/local/bin/rootisnaked"]
