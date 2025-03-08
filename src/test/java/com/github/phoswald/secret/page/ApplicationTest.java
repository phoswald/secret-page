package com.github.phoswald.secret.page;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.file.StandardOpenOption.CREATE;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.List;

import org.junit.jupiter.api.Test;

class ApplicationTest {

    private final String password = "1234";
    private final String plainText = """
        This is a sample text
        consisting of multiple lines.
        """;
    
    private final Application testee = new Application().password(password).allowOverwrite(true);

    @Test
    void prepare_valid_success() throws IOException {
        // Act
        testee.prepare(Path.of("target/test-data/"));

        // Assert
        assertThat(Files.readString(Path.of("target/test-data/crypto.js"), UTF_8), not(emptyOrNullString()));
    }

    @Test
    void encrypt_valid_success() throws IOException, GeneralSecurityException {
        // Arrange
        Path input = Path.of("target/test-data/sample.txt");
        Files.createDirectories(input.getParent());
        Files.writeString(input, plainText, UTF_8, CREATE);

        // Act
        testee.encrypt(List.of(input));

        // Assert
        assertThat(Files.readString(Path.of("target/test-data/sample.txt.html"), UTF_8), not(emptyOrNullString()));
    }

    @Test
    void encryptString_valid_success() throws GeneralSecurityException {
        // Act
        String cipherText = testee.encryptString(password, plainText);
        
        // Assert
        String[] cipherTextParts = cipherText.split(":");
        assertEquals(3, cipherTextParts.length);
        assertEquals(18, cipherTextParts[0].length() * 3 / 4);
        assertEquals(12, cipherTextParts[1].length() * 3 / 4);
        assertEquals(69, cipherTextParts[2].length() * 3 / 4);
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
