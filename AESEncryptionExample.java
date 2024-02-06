import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.HexFormat;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class AESEncryptionExample {

  public static void main(String[] args) {

    final String key = "example-key-12345670123456789012";
    try {
      String encryptedString = encryptString("Hello World!", key);
      System.out.println("Encrypted String: " + encryptedString);
      String decryptedString = decryptString(encryptedString, key);
      System.out.println("Decrypted String: " + decryptedString);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  // perform AES 256 bit encryption then base64 encode and url encode
  public static String encryptString(String plainText, String key) throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
    
    // Generate random initialization vector and salt
    byte initVector[] = new byte[16];
    new SecureRandom().nextBytes(initVector);
    byte salt[] = new byte[16];
    new SecureRandom().nextBytes(salt);

    // Create key spec from password and salt
    SecretKeySpec secretKeySpec = generateKeySpec(key, salt);

    // perform encryption of plain text
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
    cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(initVector));
    byte[] encrypted = cipher.doFinal(plainText.getBytes("UTF-8"));

    // Convert salt and initialization vector to HEX
    String saltHex = HexFormat.of().formatHex(salt);
    String initVectorHex = HexFormat.of().formatHex(initVector);

    // Base64 encode encrypted data.
    String encryptedBase64 = Base64.getEncoder().encodeToString(encrypted);

    // Concatenate salt, initialization vector, and encrypted data into a single string to be Base64 encoded and then URL encoded.
    String message = saltHex + initVectorHex + encryptedBase64;

    return URLEncoder.encode(Base64.getEncoder().encodeToString(message.getBytes()), "UTF-8");
  }

  // decrypt AES 256 bit encryption from url encoded and base64 encoded string
  public static String decryptString(String encryptedText, String key) throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {

    // Url decode and base64 decode encrypted string
    String urlDecodedString = URLDecoder.decode(encryptedText, "UTF-8");
    byte[] byteArray = Base64.getDecoder().decode(urlDecodedString);
    String message = new String(byteArray);

    // Extract salt, initialization vector, and encrypted data from the message
    byte[] salt = HexFormat.of().parseHex(message.substring(0, 32));
    byte[] iv = HexFormat.of().parseHex(message.substring(32, 64));
    byte[] encryptedBytes = Base64.getDecoder().decode(message.substring(64));

    // Generate secret key spec from shared password and salt
    SecretKeySpec secretKeySpec = generateKeySpec(key, salt);

    // perform decryption and return decrypted string
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
    cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));
    byte[] decrypted = cipher.doFinal(encryptedBytes);
    return new String(decrypted);
  }

 // generate a secret key spec from a password and salt
  public static SecretKeySpec generateKeySpec(String key, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
    KeySpec keySpec = new PBEKeySpec(key.toCharArray(), salt, 65536, 256);
    SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
    SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");
    return secretKeySpec;
  }

}