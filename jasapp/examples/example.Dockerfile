FROM ubuntu:latest
RUN apt-get update
RUN apt-get install -y python3
RUN gem install rails bundler
WORKDIR app
USER root
