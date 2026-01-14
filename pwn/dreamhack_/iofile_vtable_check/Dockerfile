FROM ubuntu:18.04
RUN apt-get update && apt-get install -y \
    gdb gdbserver python3 python3-pip \
    build-essential patchelf file binutils \
 && rm -rf /var/lib/apt/lists/*
