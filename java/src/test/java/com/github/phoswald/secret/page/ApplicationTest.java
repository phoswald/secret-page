package com.github.phoswald.secret.page;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.GeneralSecurityException;

import org.junit.jupiter.api.Test;

class ApplicationTest {
    
    private final Application testee = new Application();
    
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
}
