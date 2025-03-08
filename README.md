
# secret-page

Encrypt and Decrypt web page content using PBKDF2, SHA-256, and AES-GCM

## Web Page

~~~
$ docker run -d --rm --name mysecretpage \
  -p 8080:8080 \
  -v $(pwd):/usr/share/nginx/html:ro \
  nginxinc/nginx-unprivileged:alpine
~~~

URL: http://localhost:8080/

## Java Encoder

~~~
$ cd java
$ mvn clean verify -P native

$ java \
  -cp $(echo target/secret-page-*-dist/lib)/"*" \
  com.github.phoswald.secret.page.Application

$ file target/secret-page
$ ldd  target/secret-page

$  export SECRET_PAGE_PASSWORD=...
$ target/secret-page encrypt pom.xml
~~~

### Known Issues:

- `System.console()` does not work in native images, password must be passed as environment variable!
