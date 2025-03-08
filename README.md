
# secret-page

Encrypt and Decrypt web page content using PBKDF2, SHA-256, and AES-GCM

## Build and Run

~~~
$ mvn clean verify -P native

$ java \
  -cp $(echo target/secret-page-*-dist/lib)/"*" \
  com.github.phoswald.secret.page.Application

$ file target/secret-page
$ ldd  target/secret-page

$ export SECRET_PAGE_PASSWORD=1234
$ echo "Hello, World!" > data/test.txt
$ target/secret-page prepare data/
$ target/secret-page encrypt data/test.txt --allow-overwrite
~~~

### Known Issues:

- `System.console()` does not work in native images, password must be passed as environment variable!

## Web Page

Serve content in working directory:

~~~
$ docker run -d --rm --name mysecretpage \
  -p 8080:8080 \
  -v $(pwd)/data:/usr/share/nginx/html:ro \
  nginxinc/nginx-unprivileged:alpine
~~~

URL: http://localhost:8080/test.html
