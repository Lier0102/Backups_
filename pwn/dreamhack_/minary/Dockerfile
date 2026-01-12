FROM ubuntu:24.04@sha256:1e622c5f073b4f6bfad6632f2616c7f59ef256e96fe78bf6a595d1dc4376ac02

RUN apt update
RUN apt install adduser socat -y
RUN adduser -u 1337 pwn
WORKDIR /home/pwn
COPY ./deploy/prob ./prob
COPY ./deploy/flag ./flag
RUN chmod 755 ./prob

USER pwn

EXPOSE 8080
CMD socat TCP-LISTEN:8080,reuseaddr,fork EXEC:./prob,stderr
