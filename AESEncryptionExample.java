import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

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

    final String password = "example-key";
    final String initVector = "0123456789123456"; // Must be 16 bytes
    final String salt = "example-salt";
    try {
      String encryptedString = encryptString("Hello World!", password, salt, initVector);
      System.out.println("Encrypted String: " + encryptedString);
      String decryptedString = decryptString(encryptedString, password, salt, initVector);
      System.out.println("Decrypted String: " + decryptedString);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  // perform AES 256 bit encryption and return result as a base64 encoded string
  public static String encryptString(String plainText, String password, String salt, String initVectorString) throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
    SecretKeySpec keySpec = generateKeySpec(password, salt);
    IvParameterSpec iv = generateIV(initVectorString);

    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);
    byte[] encrypted = cipher.doFinal(plainText.getBytes("UTF-8"));
    return Base64.getEncoder().encodeToString(encrypted);
  }

  // decrypt AES 256 bit encryption from base64 encoded string
  public static String decryptString(String encryptedText, String password, String salt, String initVectorString) throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
    SecretKeySpec keySpec = generateKeySpec(password, salt);
    IvParameterSpec iv = generateIV(initVectorString);

    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.DECRYPT_MODE, keySpec, iv);
    byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
    return new String(decrypted);
  }

 // generate a secret key spec from a password and salt
  public static SecretKeySpec generateKeySpec(String password, String salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
    KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
    SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    SecretKey key = keyFactory.generateSecret(keySpec);
    SecretKeySpec secretKeySpec = new SecretKeySpec(key.getEncoded(), "AES");
    return secretKeySpec;
  }

  // generate an initialization vector (IV)
  public static IvParameterSpec generateIV(String initVectorString) throws UnsupportedEncodingException {
    byte[] initVector = initVectorString.getBytes("UTF-8");
    return new IvParameterSpec(initVector);
  }

}