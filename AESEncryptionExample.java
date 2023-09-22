import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
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

  // perform AES 256 bit encryption and return result as a base64 encoded string
  public static String encryptString(String plainText, String key) throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
    SecretKeySpec keySpec = generateKeySpec(key);

    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

    
    byte initVector[] = new byte[16];
    new SecureRandom().nextBytes(initVector);

    cipher.init(Cipher.ENCRYPT_MODE, keySpec, new GCMParameterSpec(128, initVector));
    byte[] encrypted = cipher.doFinal(plainText.getBytes("UTF-8"));

    byte[] encryptedWithIv = ByteBuffer.allocate(initVector.length + encrypted.length)
      .put(initVector)
      .put(encrypted)
      .array();
    
    return Base64.getEncoder().encodeToString(encryptedWithIv);
  }

  // decrypt AES 256 bit encryption from base64 encoded string
  public static String decryptString(String encryptedText, String key) throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {

    ByteBuffer byteBuffer = ByteBuffer.wrap(Base64.getDecoder().decode(encryptedText));
    byte[] iv = new byte[16];
    byteBuffer.get(iv, 0, iv.length);
    byte[] encryptedBytes = new byte[byteBuffer.remaining()];
    byteBuffer.get(encryptedBytes, 0, encryptedBytes.length);

    SecretKeySpec keySpec = generateKeySpec(key);

    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(128, iv));
    byte[] decrypted = cipher.doFinal(encryptedBytes);
    return new String(decrypted);
  }

 // generate a secret key spec from a password and salt
  public static SecretKeySpec generateKeySpec(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
    SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "AES");
    return secretKeySpec;
  }

}