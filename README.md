# SecurePayload

This is a simple class to enable encryption and decryption of data (of arbitrary length) using public-key (asymmetric) 
cryptography. I use this class as a library to securely transmit data from an Android client app to a Java server application.

Under the hood it works similarly to PGP. The supplied data is encrypted using a one-time session key (128-bit AES key in CBC mode). 
This session key is then encrypted using the user-supplied RSA private key (ECB mode) and packed together with the encrypted data. 
This object can hen be safely transported to a destination through any serialization mechanism. 

To decrypt, the user supplies the associate RSA private key, which unencrypts the session key and then uses the session key 
to unencrypt the cipher data to return back the unencrypted data. Gneration and exchange/transmission of the RSA keys must 
be handled yourself.

## Installing
SecurePayload can be added as a gradle or maven dependency, see instructions on link below:
https://jitpack.io/#danieldimatteo/SecurePayload/v1.1

## Sample usage:
```java
// generate 1024-bit RSA key pair
KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
keyGen.initialize(1024);
KeyPair keyPair = keyGen.generateKeyPair();

// encrypt some data in a SecurePayload with public key
String textToEncrypt = "hello world!";
byte[] bytesToEncrypt = Files.readAllBytes(Paths.get(path));
SecurePayload clientSidePayload = new SecurePayload(bytesToEncrypt, keyPair.getPublic());

// write SecurePayload to stream to simulate sending file from client to server 
ByteArrayOutputStream buffer = new ByteArrayOutputStream(); // this can be a FileOutputStream to write to file
ObjectOutputStream oos = new ObjectOutputStream(buffer);
oos.writeObject(clientSidePayload);

// read back out of stream to simulate receiving payload on server side
ByteArrayInputStream bis = new ByteArrayInputStream(buffer.toByteArray()); // this can be a FileInputStream to read from file
ObjectInputStream ois = new ObjectInputStream(bis);
SecurePayload serverSidePayload = (SecurePayload) ois.readObject();

// get unecrypted data back out of SecurePayload by providing private key
byte[] receivedBytes = serverSidePayload.getPayload(keyPair.getPrivate());
String receivedString = new String(receivedBytes, StandardCharsets.UTF_8);
```
