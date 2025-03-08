package com.github.phoswald.secret.page;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;

import java.io.IOException;
import java.security.GeneralSecurityException;

import org.junit.jupiter.api.Test;

class ApplicationTest {
    
    private final Application testee = new Application();

    @Test
    void prepare_valid_success() throws IOException {
        testee.prepare(new String[] { "prepare", "data" });
    }
    
    @Test
    void encrypt_valid_success() throws GeneralSecurityException {
        // Assert
        String password = "1234";
        String plainText = """
                <h1>Message from <span style="color:red">Java</span></h1>
                <u>Hello</u>, <b>World</b>!
                """;
        
        // Act
        String cipherText = testee.encrypt(password, plainText);
        
        // Assert
        String[] cipherTextParts = cipherText.split(":");
        assertEquals(3, cipherTextParts.length);
        assertEquals(18, cipherTextParts[0].length() * 3 / 4);
        assertEquals(12, cipherTextParts[1].length() * 3 / 4);
        assertEquals(102, cipherTextParts[2].length() * 3 / 4);
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
