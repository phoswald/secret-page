package com.github.phoswald.secret.page;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.CREATE_NEW;
import static java.nio.file.StandardOpenOption.TRUNCATE_EXISTING;

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
    private final Base64.Decoder decoder = Base64.getDecoder();

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

        } else if(args.size() >= 2 && Objects.equals(args.get(0), "decrypt")) {
            decrypt(args.subList(1, args.size()).stream().map(s -> Path.of(s).toAbsolutePath()).toList());

        } else {
            System.out.println("""
                Syntax: 
                  secret-page [OPTIONS] prepare PATH
                  secret-page [OPTIONS] encrypt MD-FILE...
                  secret-page [OPTIONS] decrypt HTML-FILE...
                Options:
                  --allow-overwrite       dont fail if target file aready exists
                Environment:
                  SECRET_PAGE_PASSWORD    password for encryption/decryption, if undefined: prompted from console
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
        outputDir = outputDir.resolve("secret-page");
        prepareFile(outputDir, "secret.ico");
        prepareFile(outputDir, "defaults.css");
        prepareFile(outputDir, "markdown.css");
        prepareFile(outputDir, "dompurify.umd.min.js");
        prepareFile(outputDir, "marked.umd.min.js");
        prepareFile(outputDir, "markdown.js");
        prepareFile(outputDir, "crypto.js");
    }

    private void prepareFile(Path outputDir, String fileName) throws IOException {
        Path outputFile = outputDir.resolve(fileName);
        byte[] outputContent = getClass().getResourceAsStream("/html/" + fileName).readAllBytes();
        logger.info("Writing: {} (size: {})", outputFile, outputContent.length);
        Files.createDirectories(outputFile.getParent());
        Files.write(outputFile, outputContent, allowOverwrite ? CREATE : CREATE_NEW, TRUNCATE_EXISTING);
    }

    void encrypt(List<Path> inputFiles) throws IOException, GeneralSecurityException {
        String password = readPassword();
        for(Path inputFile : inputFiles) {
            String fileName = inputFile.getFileName().toString();
            if(!fileName.endsWith(".md")) {
                throw new IllegalArgumentException("Encryption requires *.md files");
            }
            String baseName = fileName.replaceAll("\\.md$", "");
            Path outputFile = inputFile.getParent().resolve(baseName + ".html");
            logger.info("Reading: {}", inputFile);
            String plainText = Files.readString(inputFile, UTF_8);
            String cipherText = encryptString(password, plainText);
            String outputHtml = fillTemplate(baseName, cipherText);
            logger.info("Writing: {} (size: {})", outputFile, outputHtml.length());
            Files.writeString(outputFile, outputHtml, UTF_8, allowOverwrite ? CREATE : CREATE_NEW, TRUNCATE_EXISTING);
        }
    }

    void decrypt(List<Path> inputFiles) throws IOException, GeneralSecurityException {
        String password = readPassword();
        for(Path inputFile : inputFiles) {
            String fileName = inputFile.getFileName().toString();
            if(!fileName.endsWith(".html")) {
                throw new IllegalArgumentException("Decryption requires *.html files");
            }
            Path outputFile = inputFile.getParent().resolve(fileName.replaceAll("\\.html$", "") + ".md");
            logger.info("Reading: {}", inputFile);
            String inputHtml = Files.readString(inputFile, UTF_8);
            String cipherText = extractCipherText(inputHtml);
            String plainText = decryptString(password, cipherText);
            logger.info("Writing: {} (size: {})", outputFile, plainText.length());
            Files.writeString(outputFile, plainText, UTF_8, allowOverwrite ? CREATE : CREATE_NEW, TRUNCATE_EXISTING);
        }
    }

    String extractCipherText(String html) throws IOException {
        String startTag = "<div id=\"cipherText\" class=\"hidden\">";
        int start = html.indexOf(startTag);
        int end = start < 0 ? -1 : html.indexOf("</div>", start);
        if(start < 0 || end < 0) {
            throw new IOException("Cipher text not found");
        }
        return html.substring(start + startTag.length(), end).strip();
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

    String decryptString(String password, String cipherText) throws GeneralSecurityException {
        String[] cipherTextParts = cipherText.strip().split(":");
        if(cipherTextParts.length != 3) {
            throw new GeneralSecurityException("Invalid cipher text format");
        }
        byte[] salt = decoder.decode(cipherTextParts[0]);
        byte[] iv = decoder.decode(cipherTextParts[1]);
        SecretKey key = createKey(salt, password.toCharArray());
        byte[] plainText = decryptMessage(key, iv, decoder.decode(cipherTextParts[2]));
        return new String(plainText, UTF_8);
    }

    private SecretKey createKey(byte[] salt, char[] password) throws GeneralSecurityException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec keySpec = new PBEKeySpec(password, salt, 600000 /* iterationCount */, 256 /* keyLength */);
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

    private byte[] decryptMessage(SecretKey key, byte[] iv, byte[] cipherText) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128 /* auth tag length */, iv));
        byte[] plainText = cipher.doFinal(cipherText);
        return plainText;
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
