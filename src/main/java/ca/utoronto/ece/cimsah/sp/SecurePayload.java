package ca.utoronto.ece.cimsah.sp;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.Serializable;
import java.security.*;

public class SecurePayload implements Serializable {
    private byte[] cipherData;
    private byte[] encryptedSessionKey;
    private byte[] iv;

    public SecurePayload(byte[] plaintextData, PublicKey publicKey) throws GeneralSecurityException {
        // generate a random session key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey sessionKey = keyGen.generateKey();  // generate random secret key

        // use session key to encrypt payload. In the process, create and save initialization vector
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        SecureRandom secureRandom = new SecureRandom();
        byte[] ivBytes = new byte[aesCipher.getBlockSize()];
        secureRandom.nextBytes(ivBytes);
        iv = ivBytes.clone();
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
        aesCipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivParameterSpec);
        cipherData = aesCipher.doFinal(plaintextData);

        // wrap (encrypt) session key with user's public key and save
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.WRAP_MODE, publicKey);
        encryptedSessionKey = rsaCipher.wrap(sessionKey);
    }

    public byte[] getPayload(PrivateKey privateKey) throws GeneralSecurityException {
        // unwrap the session key
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.UNWRAP_MODE, privateKey);
        Key sessionKey = rsaCipher.unwrap(encryptedSessionKey, "AES", Cipher.SECRET_KEY);

        // decrypt payload using session key and initialization vector
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        aesCipher.init(Cipher.DECRYPT_MODE, sessionKey, ivParameterSpec);
        return aesCipher.doFinal(cipherData);
    }

    public byte[] getCipherData() {
        return cipherData;
    }

}
