package dukpt.util;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class DESCryptoUtil {
  // private static String TRIPLE_DES_TRANSFORMATION = "DESede/ECB/NoPadding";
  private static String TRIPLE_DES_TRANSFORMATION = "DESede/CBC/NoPadding";
  private static String ALGORITHM = "DESede";
  private static byte[] iv = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  public static byte[] tdesEncrypt(byte[] input, byte[] key)
      throws IllegalBlockSizeException,
      BadPaddingException, NoSuchAlgorithmException, NoSuchProviderException,
      NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
    if (key.length != 16 && key.length != 24) {
      throw new InvalidKeyException(
          "@ DESCryptoUtil.tdesEncrypt(). Parameter <key> must be 16 or 24 bytes long (bouble/triple key), but was "
              + key.length + ".");
    }

    if (key.length == 16) {
      key = extendDoubleKeyToTripleKey(key);
    }

    IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

    SecretKey keySpec = new SecretKeySpec(key, ALGORITHM);
    Cipher encrypter = Cipher.getInstance(TRIPLE_DES_TRANSFORMATION);
    encrypter.init(Cipher.ENCRYPT_MODE, keySpec, ivParameterSpec);

    return encrypter.doFinal(input);
  }

  public static byte[] tdesDecrypt(byte[] input, byte[] key)
      throws IllegalBlockSizeException,
      BadPaddingException, NoSuchAlgorithmException, NoSuchProviderException,
      NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
    if (key.length != 16 && key.length != 24) {
      throw new InvalidKeyException(
          "@ DESCryptoUtil.tdesDecrypt(). Parameter <key> must be 16 or 24 bytes long (bouble/triple key), but was "
              + key.length + ".");
    }

    if (key.length == 16) {
      key = extendDoubleKeyToTripleKey(key);
    }

    IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

    SecretKey keySpec = new SecretKeySpec(key, ALGORITHM);
    Cipher cipher = Cipher.getInstance(TRIPLE_DES_TRANSFORMATION);
    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParameterSpec);

    return cipher.doFinal(input);
  }

  public static byte[] desEncrypt(byte[] input, byte[] key) throws NoSuchAlgorithmException,
      NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    if (key.length != 8) {
      throw new InvalidKeyException(
          "@ DESCryptoUtil.desEncrypt(). Parameter <key> must be 8 bytes long, but was "
              + key.length + ".");
    }

    if (input.length != 8) {
      throw new IllegalBlockSizeException(
          "@ DESCryptoUtil.desEncrypt(). Parameter <input> must be 8 bytes long, but was "
              + input.length + ".");
    }

    Cipher desCipher = Cipher.getInstance("DES/ECB/NoPadding");
    SecretKey keySpec = new SecretKeySpec(key, "DES");
    desCipher.init(Cipher.ENCRYPT_MODE, keySpec);

    return desCipher.doFinal(input);
  }

  private static byte[] extendDoubleKeyToTripleKey(byte[] doubleKey) {
    byte[] tripleKey = new byte[24];

    for (int i = 0; i < 16; i++) {
      tripleKey[i] = doubleKey[i];
    }

    for (int i = 0, j = 16; j < 24; i++, j++) {
      tripleKey[j] = doubleKey[i];
    }

    return tripleKey;
  }
}
