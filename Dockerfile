FROM ubuntu
WORKDIR /src

# Tools
RUN apt update && apt upgrade -y
RUN apt install -y curl lldb clang wget cmake git libc++-15-dev libc++abi-15-dev python3-pip m4 texinfo
RUN pip3 install conan

# Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain 1.63.0 -y
ENV PATH=/root/.cargo/bin:$PATH
RUN rustup toolchain install nightly
RUN cargo +nightly install -Z sparse-registry --force cargo-make

# Go
RUN wget -c https://go.dev/dl/go1.19.linux-amd64.tar.gz
RUN rm -rf /usr/local/go
RUN tar -C /usr/local -xvzf go1.19.linux-amd64.tar.gz
ENV PATH=$PATH:/usr/local/go/bin:/root/go/bin
RUN go install github.com/dvyukov/go-fuzz/go-fuzz-build@latest

RUN apt remove gcc
