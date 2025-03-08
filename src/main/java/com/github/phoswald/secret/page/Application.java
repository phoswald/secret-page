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
        if(args.length == 2 && Objects.equals(args[0], "prepare")) {
            prepare(args);

        } else if (args.length == 2  && Objects.equals(args[0], "encrypt")) {
            encrypt(args);

        } else {
            System.out.println("Syntax:");
            System.out.println("  $ secret-page prepare <path>");
            System.out.println("  $ secret-page encrypt <input.txt>");
        }
    }

    void prepare(String[] args) throws IOException {
        Path outputFile = Paths.get(args[1], "crypto.js").toAbsolutePath();
        String outputJs = new String(getClass().getResourceAsStream("/html/crypto.js").readAllBytes(), UTF_8);
        logger.info("Writing: {}", outputFile);
        Files.writeString(outputFile, outputJs, UTF_8, StandardOpenOption.CREATE);
        logger.info("Success.");
    }

    void encrypt(String[] args) throws IOException, GeneralSecurityException {
        Path inputFile = Paths.get(args[1]).toAbsolutePath();
        String baseName = inputFile.getFileName().toString().replaceAll("\\.[a-zA-z0-9]+$", "");
        Path outputFile = inputFile.getParent().resolve(baseName + ".html");
        logger.info("Input: {}", inputFile);
        logger.info("Output: {}", outputFile);
        logger.info("Name: {}", baseName);
        byte[] plainText = Files.readAllBytes(inputFile);
        char[] password = readPassword();
        String cipherText = encrypt(password, plainText);
        String outputHtml = fillTemplate(baseName, cipherText);
        Files.writeString(outputFile, outputHtml, UTF_8, StandardOpenOption.CREATE_NEW);
        logger.info("Success.");
    }

    private char[] readPassword() {
        String propertyName = "SECRET_PAGE_PASSWORD";
        String propertyValue = System.getenv(propertyName);
        if (propertyValue != null) {
            logger.info("Using {}", propertyName);
            return propertyValue.toCharArray();
        } else {
            return System.console().readPassword("Password: ");
        }
    }

    String fillTemplate(String name, String cipherText) throws IOException {
        String template = new String(getClass().getResourceAsStream("/html/template.html").readAllBytes(), UTF_8);
        return template.replace("${NAME}", name).replace("${CIPHERTEXT}", cipherText);
    }

    String encrypt(String password, String plainText) throws GeneralSecurityException {
        return encrypt(password.toCharArray(), plainText.getBytes(UTF_8));
    }

    private String encrypt(char[] password, byte[] plainText) throws GeneralSecurityException {
        byte[] salt = fillRandom(new byte[16]);
        byte[] iv = fillRandom(new byte[12]);
        SecretKey key = createKey(salt, password);
        byte[] cipherText = encryptMessage(key, iv, plainText);
        String cipherTextParts = encoder.encodeToString(salt) + ":" + //
                encoder.encodeToString(iv) + ":" + //
                encoder.encodeToString(cipherText);
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
