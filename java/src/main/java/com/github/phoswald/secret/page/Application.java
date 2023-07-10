package com.github.phoswald.secret.page;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Application {

    private static final Logger logger = LoggerFactory.getLogger(Application.class);
    private final SecureRandom sr = new SecureRandom();
    private final Base64.Encoder encoder = Base64.getEncoder();

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        new Application().run(args);
    }

    void run(String[] args) throws IOException, GeneralSecurityException {
        if (args.length != 3 || !Objects.equals(args[0], "encrypt")) {
            System.out.println("Syntax:");
            System.out.println("  $ secret-page encrypt <input-file> <output-file>");
            return;
        }
        Path inputFile = Paths.get(args[1]).toAbsolutePath();
        Path outputFile = Paths.get(args[2]).toAbsolutePath();
        byte[] plainText = Files.readAllBytes(inputFile);
        logger.info("Read {} ({} bytes)", inputFile, plainText.length);
        char[] password = System.console().readPassword("Password: ");
        String cipherTextParts = encrypt(password, plainText);
        Files.writeString(outputFile, cipherTextParts, UTF_8, StandardOpenOption.CREATE_NEW);
        logger.info("Written {} ({} chars)", outputFile, cipherTextParts.length());
    }
    
    String encrypt(String password, String plainText) throws GeneralSecurityException {
        return encrypt(password.toCharArray(), plainText.getBytes(UTF_8));
    }

    String encrypt(char[] password, byte[] plainText) throws GeneralSecurityException {
        byte[] salt = fillRandom(new byte[16]);
        byte[] iv = fillRandom(new byte[12]);
        SecretKey key = createKey(salt, password);
        byte[] cipherText = encryptMessage(key, iv, plainText);
        String cipherTextParts = encoder.encodeToString(salt) + ":" + //
                encoder.encodeToString(iv) + ":" + //
                encoder.encodeToString(cipherText);
        logger.info("cipherText: {}", cipherTextParts);
        return cipherTextParts;
    }

    private SecretKey createKey(byte[] salt, char[] password) throws GeneralSecurityException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec keySpec = new PBEKeySpec(password, salt, 100000 /* iterationCount */, 256 /* keyLength */);
        SecretKey key1 = factory.generateSecret(keySpec);
        SecretKey key2 = new SecretKeySpec(key1.getEncoded(), "AES");
        return key2;
    }

    private byte[] encryptMessage(SecretKey key, byte[] iv, byte[] plainText) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128 /* auth tag length */, iv));
        byte[] cipherText = cipher.doFinal(plainText);
        return cipherText;
    }

    private byte[] fillRandom(byte[] buffer) {
        sr.nextBytes(buffer);
        return buffer;
    }
}
