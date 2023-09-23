#!/bin/bash
native-image \
  --no-fallback \
  --static \
  -H:+UnlockExperimentalVMOptions \
  -H:IncludeResources="^template.html$" \
  -cp $(echo target/secret-page-*-dist/lib)/"*" \
  com.github.phoswald.secret.page.Application \
  target/secret-page
