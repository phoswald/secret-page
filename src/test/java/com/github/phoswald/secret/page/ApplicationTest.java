package com.github.phoswald.secret.page;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.file.StandardOpenOption.CREATE;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.List;

import org.junit.jupiter.api.Test;

class ApplicationTest {

    private static final String PASSWORD = "1234";
    private static final String CIPHER_TEXT = "4auseYysZKy1jZWkE42vmg:ciZuYJsFlTZVpYPA:9DqdGP9rVdwmXuM3urW9j0GhsQIe85zcGgQsy9fuGpcKIU/V7PdAFrtnPB4B/qr9Z9wEQ4DYYMQepzsfFbLyF5t/EVM";
    private static final String PLAIN_TEXT = """
        This is a sample text
        consisting of multiple lines.
        """;
    
    private final Application testee = new Application().password(PASSWORD).allowOverwrite(true);

    @Test
    void prepare_valid_success() throws IOException {
        // Act
        testee.prepare(Path.of("target/test-data/"));

        // Assert
        assertThat(Files.readAllBytes(Path.of("target/test-data/secret-page/secret.ico")).length, equalTo(17014));
        assertThat(Files.readString(Path.of("target/test-data/secret-page/defaults.css"), UTF_8), not(emptyOrNullString()));
        assertThat(Files.readString(Path.of("target/test-data/secret-page/markdown.css"), UTF_8), not(emptyOrNullString()));
        assertThat(Files.readString(Path.of("target/test-data/secret-page/dompurify.umd.min.js"), UTF_8), not(emptyOrNullString()));
        assertThat(Files.readString(Path.of("target/test-data/secret-page/marked.umd.min.js"), UTF_8), not(emptyOrNullString()));
        assertThat(Files.readString(Path.of("target/test-data/secret-page/markdown.js"), UTF_8), not(emptyOrNullString()));
        assertThat(Files.readString(Path.of("target/test-data/secret-page/crypto.js"), UTF_8), not(emptyOrNullString()));
    }

    @Test
    void encrypt_valid_success() throws IOException, GeneralSecurityException {
        // Arrange
        Path input = Path.of("target/test-data/encrypt.md");
        Files.createDirectories(input.getParent());
        Files.writeString(input, PLAIN_TEXT, UTF_8, CREATE);

        // Act
        testee.encrypt(List.of(input));

        // Assert
        assertThat(Files.readString(Path.of("target/test-data/encrypt.html"), UTF_8), not(emptyOrNullString()));
    }

    @Test
    void encrypt_notMd_failure() throws IOException {
        // Arrange
        Path input = Path.of("target/test-data/encrypt.txt");
        Files.createDirectories(input.getParent());
        Files.writeString(input, PLAIN_TEXT, UTF_8, CREATE);

        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> testee.encrypt(List.of(input)));
    }

    @Test
    void decrypt_valid_success() throws IOException, GeneralSecurityException {
        // Arrange
        Path input = Path.of("target/test-data/decrypt.html");
        Files.createDirectories(input.getParent());
        Files.writeString(input, testee.fillTemplate("decrypt", CIPHER_TEXT), UTF_8, CREATE);

        // Act
        testee.decrypt(List.of(input));

        // Assert
        assertEquals(PLAIN_TEXT, Files.readString(Path.of("target/test-data/decrypt.md"), UTF_8));
    }

    @Test
    void decrypt_notHtml_failure() throws IOException {
        // Arrange
        Path input = Path.of("target/test-data/decrypt.txt");
        Files.createDirectories(input.getParent());
        Files.writeString(input, testee.fillTemplate("decrypt", CIPHER_TEXT), UTF_8, CREATE);

        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> testee.decrypt(List.of(input)));
    }

    @Test
    void encryptString_valid_success() throws GeneralSecurityException {
        // Act
        String cipherText = testee.encryptString(PASSWORD, PLAIN_TEXT);

        // Assert
        String[] cipherTextParts = cipherText.split(":");
        assertEquals(3, cipherTextParts.length);
        assertEquals(16 /* salt bytes */, cipherTextParts[0].length() * 3 / 4);
        assertEquals(12 /* iv bytes */, cipherTextParts[1].length() * 3 / 4);
        assertEquals(PLAIN_TEXT.length() + 16 /* checksum bytes */, cipherTextParts[2].length() * 3 / 4);
    }

    @Test
    void decryptString_valid_success() throws GeneralSecurityException {
        // Act
        String plainText = testee.decryptString(PASSWORD, CIPHER_TEXT);

        // Assert
        assertEquals(PLAIN_TEXT, plainText);
    }

    @Test
    void fillTemplate_valid_success() throws IOException {
        // Act
        String html = testee.fillTemplate("Sample", "0123456789ABCDEF");

        // Assert
        assertThat(html, startsWith("<!DOCTYPE html>\n"));
        assertThat(html, containsString("<title>Sample</title>"));
        assertThat(html, containsString("\n    0123456789ABCDEF\n"));
    }
}
