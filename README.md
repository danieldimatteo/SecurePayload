# SecurePayload

This is a simple class to enable encrypting and decrypting of data using 1024-bit RSA key pairs by performing symmetric (AES) 
encryption under the hood.

The supplied data is encrypted using a one-time session key (128-bit AES key in CBC mode). This session key is then 
encrypted using the user-supplied RSA private key (ECB mode) and packed together with the encrypted data. This object can
then be safely transported to a destination through any serialization mechanism. 

To decrypt, the user supplies the associate RSA private key, which unencrypts the session key and then uses the session key 
to unencrypt the cipher data to return back the unencrypted data.

I use this class as a library to securely transmit data from an Android client app to a Java server application. Of course, 
generation and exchange/transmission of the RSA keys must be handled yourself.

Sample usage:
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
