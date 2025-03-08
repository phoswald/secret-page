package com.github.phoswald.secret.page;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.CREATE_NEW;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
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

    private String password = null;
    private boolean allowOverwrite = false;

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        new Application().run(Arrays.asList(args));
    }

    void run(List<String> args) throws IOException, GeneralSecurityException {
        args = new ArrayList<>(args);
        for(int i = 0; i < args.size(); i++) {
            if(args.get(i).equals("--allow-overwrite")) {
                allowOverwrite(true);
                args.remove(i); i--;
            }
        }

        if(args.size() == 2 && Objects.equals(args.get(0), "prepare")) {
            prepare(Path.of(args.get(1)).toAbsolutePath());

        } else if(args.size() >= 2 && Objects.equals(args.get(0), "encrypt")) {
            encrypt(args.subList(1, args.size()).stream().map(s -> Path.of(s).toAbsolutePath()).toList());

        } else {
            System.out.println("""
                Syntax: 
                  secret-page [OPTIONS] prepare PATH
                  secret-page [OPTIONS] encrypt FILE...
                Options:
                  --allow-overwrite       dont fail if target file aready exists
                Environment:
                  SECRET_PAGE_PASSWORD    password for encryption, if undefined: prompted from console
                """);
        }
    }

    Application password(String value) {
        password = value;
        return this;
    }

    Application allowOverwrite(boolean value) {
        allowOverwrite = value;
        return this;
    }

    void prepare(Path outputDir) throws IOException {
        Path outputFile = outputDir.resolve("crypto.js");
        String outputJs = new String(getClass().getResourceAsStream("/html/crypto.js").readAllBytes(), UTF_8);
        logger.info("Writing: {} (size: {})", outputFile, outputJs.length());
        Files.createDirectories(outputFile.getParent());
        Files.writeString(outputFile, outputJs, UTF_8, allowOverwrite ? CREATE : CREATE_NEW);
    }

    void encrypt(List<Path> inputFiles) throws IOException, GeneralSecurityException {
        String password = readPassword();
        for(Path inputFile : inputFiles) {
            String fileName = inputFile.getFileName().toString();
            String baseName = fileName.replaceAll("\\.[a-zA-z0-9]+$", "");
            Path outputFile = inputFile.getParent().resolve(fileName + ".html");
            logger.info("Reading: {}", inputFile);
            String plainText = Files.readString(inputFile, UTF_8);
            String cipherText = encryptString(password, plainText);
            String outputHtml = fillTemplate(baseName, cipherText);
            logger.info("Writing: {} ('{}', size: {})", outputFile, baseName, outputHtml.length());
            Files.writeString(outputFile, outputHtml, UTF_8, allowOverwrite ? CREATE : CREATE_NEW);
        }
    }

    private String readPassword() {
        if(password != null && !password.isEmpty()) {
            return password;
        }
        String propertyName = "SECRET_PAGE_PASSWORD";
        String propertyValue = System.getenv(propertyName);
        if (propertyValue != null && !propertyValue.isEmpty()) {
            logger.info("Reading password from {}", propertyName);
            return propertyValue;
        } else {
            return new String(System.console().readPassword("Password: "));
        }
    }

    String encryptString(String password, String plainText) throws GeneralSecurityException {
        byte[] salt = fillRandom(new byte[16]);
        byte[] iv = fillRandom(new byte[12]);
        SecretKey key = createKey(salt, password.toCharArray());
        byte[] cipherText = encryptMessage(key, iv, plainText.getBytes(UTF_8));
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

    String fillTemplate(String name, String cipherText) throws IOException {
        String template = new String(getClass().getResourceAsStream("/html/template.html").readAllBytes(), UTF_8);
        return template.replace("${NAME}", name).replace("${CIPHERTEXT}", cipherText);
    }
}
