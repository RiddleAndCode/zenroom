# build

FROM python:3.5-alpine AS builder

WORKDIR /code
RUN apk add --no-cache vim cmake build-base zsh linux-headers git swig
COPY . .

RUN make clean; make musl-python3

# runtime

FROM python:3.5-alpine

WORKDIR app
COPY --from=builder /code/build/python3 build/python3
COPY --from=builder /code/benchmarks benchmarks

ENTRYPOINT ["python"]

# tag

ARG BUILD_DATE
ARG VERSION
ARG VCS_URL
ARG VCS_REF

LABEL org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.name="Zenroom VM" \
      org.label-schema.description="Base docker for Zenroom operations in native x86 64bit" \
      org.label-schema.url="https://zenroom.dyne.org" \
      org.label-schema.vcs-url=$VCS_URL \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.vendor="Dyne.org" \
      org.label-schema.version=$VERSION \
      org.label-schema.schema-version="1.0" \
      org.dyne.zenroom.docker.dockerfile="/Dockerfile" \
      org.dyne.zenroom.license="GPL-3.0-only" \
      maintainer="Puria Nafisi Azizi <puria@dyne.org>" \
      homepage=$VCS_URL
