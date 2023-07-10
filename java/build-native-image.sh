#!/bin/bash
docker run -it --rm \
  -v $(pwd)/target:/target \
  -w / \
  ghcr.io/graalvm/native-image:22.3.2 \
  --no-fallback \
  --static \
  -H:IncludeResources=".*" \
  -Dfile.encoding=UTF-8 \
  -cp $(echo target/secret-page-*-dist/lib)/"*" \
  com.github.phoswald.secret.page.Application \
  target/secret-page
