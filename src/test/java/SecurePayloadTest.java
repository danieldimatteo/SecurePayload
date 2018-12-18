import ca.utoronto.ece.cimsah.sp.SecurePayload;
import org.junit.Test;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import static org.junit.Assert.*;

public class SecurePayloadTest {

    @Test
    public void testSmall() throws GeneralSecurityException {
        final String expectedPlainText = "hello world!";
        final byte[] expectedBytes = expectedPlainText.getBytes(StandardCharsets.UTF_8);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair keyPair = keyGen.generateKeyPair();

        SecurePayload securePayload = new SecurePayload(expectedBytes, keyPair.getPublic());
        byte[] plainTextBytes = securePayload.getPayload(keyPair.getPrivate());

        assertArrayEquals(expectedBytes, plainTextBytes);

        final String plainText = new String(plainTextBytes, StandardCharsets.UTF_8);
        assertEquals(expectedPlainText, plainText);
    }

    @Test
    public void testBigTextFile() throws IOException, GeneralSecurityException {
        String path = this.getClass().getClassLoader().getResource("bigtext.txt").getPath();
        byte[] expectedBytes = Files.readAllBytes(Paths.get(path));

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair keyPair = keyGen.generateKeyPair();

        SecurePayload securePayload = new SecurePayload(expectedBytes, keyPair.getPublic());
        byte[] plainTextBytes = securePayload.getPayload(keyPair.getPrivate());

        assertArrayEquals(expectedBytes, plainTextBytes);

        final String plainText = new String(plainTextBytes, StandardCharsets.UTF_8);
        final String expectedPlainText = new String(expectedBytes, StandardCharsets.UTF_8);
        assertEquals(expectedPlainText, plainText);
    }

    @Test
    public void testSerializingAudioFile() throws IOException, GeneralSecurityException, ClassNotFoundException {
        String path = this.getClass().getClassLoader().getResource("quick_brown_fox.3gp").getPath();
        byte[] expectedBytes = Files.readAllBytes(Paths.get(path));

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair keyPair = keyGen.generateKeyPair();

        SecurePayload clientSidePayload = new SecurePayload(expectedBytes, keyPair.getPublic());

        // write to stream to simulate sending file from client to server
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(buffer);
        oos.writeObject(clientSidePayload);

        // read back out of stream to simulate receiving payload on server side
        ByteArrayInputStream bis = new ByteArrayInputStream(buffer.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(bis);
        SecurePayload serverSidePayload = (SecurePayload) ois.readObject();

        byte[] receivedBytes = serverSidePayload.getPayload(keyPair.getPrivate());

        assertArrayEquals(expectedBytes, receivedBytes);
    }


    @Test
    public void testWithKeyPairSerialization() throws GeneralSecurityException {
        final String expectedPlainText = "hello world!";
        final byte[] expectedBytes = expectedPlainText.getBytes(StandardCharsets.UTF_8);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
        byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

        SecurePayload securePayload = new SecurePayload(expectedBytes, publicKey);
        byte[] plainTextBytes = securePayload.getPayload(privateKey);

        assertArrayEquals(expectedBytes, plainTextBytes);

        final String plainText = new String(plainTextBytes, StandardCharsets.UTF_8);
        assertEquals(expectedPlainText, plainText);
    }
}