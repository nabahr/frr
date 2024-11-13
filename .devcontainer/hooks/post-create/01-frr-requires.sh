#!/bin/bash

sudo apt-get update -y
sudo DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
    git \
    clang-format \
    autoconf \
    automake \
    libtool \
    make \
    libprotobuf-c-dev \
    protobuf-c-compiler \
    build-essential \
    python3-dev \
    python3-pytest \
    python3-sphinx \
    libjson-c-dev \
    libelf-dev \
    libreadline-dev \
    cmake \
    libcap-dev \
    bison \
    flex \
    pkg-config \
    texinfo \
    gdb \
    libgrpc-dev \
    python3-grpc-tools \
    libsnmp-dev \
    libpcre2-dev \
    cmake
