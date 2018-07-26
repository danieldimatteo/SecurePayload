import ca.utoronto.ece.cimsah.sp.SecurePayload;
import org.junit.Test;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;

import static org.junit.Assert.*;

public class SecurePayloadTest {

    @Test
    public void testSmall() {
        final String expectedPlainText = "hello world!";
        final byte[] expectedBytes = expectedPlainText.getBytes(StandardCharsets.UTF_8);

        KeyPairGenerator keyGen = null;
        try {
            keyGen = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            fail(e.getMessage());
        }
        keyGen.initialize(512);
        KeyPair keyPair = keyGen.generateKeyPair();

        SecurePayload securePayload = null;
        try {
            securePayload = new SecurePayload(expectedBytes, keyPair.getPublic());
        } catch (GeneralSecurityException e) {
            fail(e.getMessage());
        }

        byte[] plainTextBytes = null;
        try {
            plainTextBytes = securePayload.getPayload(keyPair.getPrivate());
        } catch (GeneralSecurityException e) {
            fail(e.getMessage());
        }

        assertArrayEquals(expectedBytes, plainTextBytes);

        final String plainText = new String(plainTextBytes, StandardCharsets.UTF_8);
        assertEquals(expectedPlainText, plainText);
    }

    @Test
    public void testBigTextFile() {
        String path = this.getClass().getClassLoader().getResource("bigtext.txt").getPath();
        byte[] expectedBytes = null;
        try {
            expectedBytes = Files.readAllBytes(Paths.get(path));
        } catch (IOException e) {
            fail(e.getMessage());
        }

        KeyPairGenerator keyGen = null;
        try {
            keyGen = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            fail(e.getMessage());
        }
        keyGen.initialize(512);
        KeyPair keyPair = keyGen.generateKeyPair();

        SecurePayload securePayload = null;
        try {
            securePayload = new SecurePayload(expectedBytes, keyPair.getPublic());
        } catch (GeneralSecurityException e) {
            fail(e.getMessage());
        }

        byte[] plainTextBytes = null;
        try {
            plainTextBytes = securePayload.getPayload(keyPair.getPrivate());
        } catch (GeneralSecurityException e) {
            fail(e.getMessage());
        }

        assertArrayEquals(expectedBytes, plainTextBytes);

        final String plainText = new String(plainTextBytes, StandardCharsets.UTF_8);
        final String expectedPlainText = new String(expectedBytes, StandardCharsets.UTF_8);
        assertEquals(expectedPlainText, plainText);
    }

    @Test
    public void testSerializingAudioFile() {
        String path = this.getClass().getClassLoader().getResource("quick_brown_fox.3gp").getPath();
        byte[] expectedBytes = null;
        try {
            expectedBytes = Files.readAllBytes(Paths.get(path));
        } catch (IOException e) {
            fail(e.getMessage());
        }

        KeyPairGenerator keyGen = null;
        try {
            keyGen = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            fail(e.getMessage());
        }
        keyGen.initialize(512);
        KeyPair keyPair = keyGen.generateKeyPair();

        SecurePayload clientSidePayload = null;
        try {
            clientSidePayload = new SecurePayload(expectedBytes, keyPair.getPublic());
        } catch (GeneralSecurityException e) {
            fail(e.getMessage());
        }

        // write to stream to simulate sending file from client to server
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        ObjectOutputStream oos = null;
        try {
            oos = new ObjectOutputStream(buffer);
        } catch (IOException e) {
            fail(e.getMessage());
        }
        try {
            oos.writeObject(clientSidePayload);
        } catch (IOException e) {
            fail(e.getMessage());
        }

        // read back out of stream to simulate receiving payload on server side
        ByteArrayInputStream bis = new ByteArrayInputStream(buffer.toByteArray());
        ObjectInputStream ois = null;
        try {
            ois = new ObjectInputStream(bis);
        } catch (IOException e) {
            fail(e.getMessage());
        }

        SecurePayload serverSidePayload = null;
        try {
            serverSidePayload = (SecurePayload) ois.readObject();
        } catch (IOException e) {
            fail(e.getMessage());
        } catch (ClassNotFoundException e) {
            fail(e.getMessage());
        }

        byte[] receivedBytes = null;
        try {
            receivedBytes = serverSidePayload.getPayload(keyPair.getPrivate());
        } catch (GeneralSecurityException e) {
            fail(e.getMessage());
        }

        assertArrayEquals(expectedBytes, receivedBytes);
    }
}