FROM ubuntu:22.04@sha256:33d782143e3a76315de8570db1673fda6d5b17c854190b74e9e890d8e95c85cf AS base
WORKDIR /app
RUN apt-get -y update --fix-missing && apt-get -y install
RUN apt-get -y install gcc
COPY bofand.c .
RUN gcc -o run bofand.c -no-pie -fno-stack-protector
COPY flag.txt /flag.txt
RUN chmod 444 /flag.txt

# use the jail base image
FROM pwn.red/jail

# copy the root files from any Docker image
COPY --from=base / /srv
# setup the binary to run
RUN /srv/app/run
