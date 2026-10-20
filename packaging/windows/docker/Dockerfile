FROM ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac AS build
ENV DEBIAN_FRONTEND=noninteractive \
    WINEARCH=win64 \
    WINEPREFIX=/opt/zenvore-wine \
    WINEDEBUG=-all
# Use only x64 Wine: 32-bit Windows bootstraps are incompatible with Rosetta.
RUN apt-get update \
    && apt-get install -y --no-install-recommends wine64 xvfb xauth curl ca-certificates python3 msitools \
    && rm -rf /var/lib/apt/lists/*
RUN printf '#!/bin/sh\nexec /usr/lib/wine/wine64 "$@"\n' > /usr/local/bin/wine \
    && printf '#!/bin/sh\nexec /usr/lib/wine/wineserver64 "$@"\n' > /usr/local/bin/wineserver \
    && chmod +x /usr/local/bin/wine /usr/local/bin/wineserver
RUN apt-get update && apt-get install -y --no-install-recommends nsis && rm -rf /var/lib/apt/lists/*
ENV PYTHON_VERSION=3.13.16 ZENVORE_WINE_BUILD=1
COPY python-msi.sha256 /opt/python-msi.sha256
COPY download.sh /opt/download.sh
RUN bash /opt/download.sh
COPY provision.sh /opt/provision.sh
COPY wine_compat.py /opt/wine_compat.py
COPY build.sh /opt/build.sh
WORKDIR /build
COPY source /source
ARG API_URL
RUN --mount=type=tmpfs,target=/opt/zenvore-wine --mount=type=tmpfs,target=/build \
    mkdir -p /artifacts && xvfb-run -a bash /opt/build.sh "$API_URL"

FROM scratch AS artifact
COPY --from=build /artifacts/ /
