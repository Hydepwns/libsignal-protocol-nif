# Multi-stage Dockerfile for libsignal-protocol-nif
FROM erlang:25-alpine AS base

# Install build dependencies
RUN apk add --no-cache \
    build-base \
    cmake \
    openssl-dev \
    git \
    curl

# Set working directory
WORKDIR /app

# Copy source code
COPY . .

# Build stage for Erlang
FROM base AS erlang-build
RUN make build && make test

# Build stage for Elixir
FROM elixir:1.16-alpine AS elixir-build
RUN apk add --no-cache build-base cmake openssl-dev git
WORKDIR /app
COPY . .
COPY --from=erlang-build /app/priv ./priv
RUN cd wrappers/elixir && \
    mix local.hex --force && \
    mix local.rebar --force && \
    mix deps.get && \
    mix compile && \
    mix test

# Build stage for Gleam
FROM ghcr.io/gleam-lang/gleam:latest AS gleam-build
RUN apk add --no-cache build-base cmake openssl-dev git
WORKDIR /app
COPY . .
COPY --from=erlang-build /app/priv ./priv
RUN cd wrappers/gleam && \
    gleam build && \
    gleam test

# Production stage
FROM erlang:25-alpine AS production
RUN apk add --no-cache openssl
WORKDIR /app
COPY --from=erlang-build /app/priv ./priv
COPY --from=erlang-build /app/lib ./lib
COPY --from=erlang-build /app/src ./src
COPY --from=erlang-build /app/include ./include
COPY --from=erlang-build /app/rebar.config ./
COPY --from=erlang-build /app/Makefile ./

# Create non-root user
RUN addgroup -g 1000 signal && \
    adduser -D -s /bin/sh -u 1000 -G signal signal
USER signal

EXPOSE 8080
CMD ["erl", "-noshell", "-s", "libsignal_protocol_nif", "start"] 