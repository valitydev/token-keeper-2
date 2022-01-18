FROM ghcr.io/rbkmoney/build-erlang:785d48cbfa7e7f355300c08ba9edc6f0e78810cb AS builder
RUN mkdir /build
COPY . /build/
WORKDIR /build
RUN rebar3 compile
RUN rebar3 as prod release

# Keep in sync with Erlang/OTP version in build image
FROM erlang:24.1.3.0-slim
ENV SERVICE=token_keeper
ENV INFRA_SERVICE=token-keeper
ENV CHARSET=UTF-8
ENV LANG=C.UTF-8
COPY --from=builder /build/_build/prod/rel/${SERVICE} /opt/${INFRA_SERVICE}
WORKDIR /opt/${INFRA_SERVICE}
ENTRYPOINT []
CMD /opt/${INFRA_SERVICE}/bin/${SERVICE} foreground
EXPOSE 8022