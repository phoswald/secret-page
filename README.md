
# secret-page

Encrypt and Decrypt web page content using PBKDF2, SHA-256, and AES-GCM

## Web Page

~~~
$ nginx-start $(pwd)/web/ 8080
~~~

URL: http://localhost:8080/

## Java Encoder

~~~
$ cd java
$ mvn clean verify && ./build-native-image.sh

$ java \
  -cp $(echo target/secret-page-*-dist/lib)/"*" \
  com.github.phoswald.secret.page.Application

$ file target/secret-page
$ ldd  target/secret-page

$ target/secret-page
~~~
