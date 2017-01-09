package dukpt.client;

import dukpt.util.ByteArrayUtil;
import dukpt.util.DESCryptoUtil;
import dukpt.util.DUKPTUtil;
import dukpt.util.StringUtil;

import org.apache.commons.codec.binary.Hex;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class TestDukpt {
  public static void main(String[] args) throws InvalidKeyException, IllegalBlockSizeException,
      BadPaddingException, NoSuchAlgorithmException, NoSuchProviderException,
      NoSuchPaddingException, InvalidAlgorithmParameterException {

    TestDukpt testDukpt = new TestDukpt();

    String keySerialNumber = "FFFF2222227070000001";
    String initialPinEncryptionKey = "9B8269417F61C26A4AC5EC57412D1E10";
    String chdPlainData = "486F77446F657333646573576F726B3F0000000000000000";

    System.out.println("\nEncrypted Data : "
        + testDukpt.dukptEncryption(keySerialNumber, initialPinEncryptionKey, chdPlainData));

  }

  public String dukptEncryption(String keySerialNumber, String initialPinEncryptionKey,
      String chdPlainData) throws InvalidKeyException,
      IllegalBlockSizeException,
      BadPaddingException, NoSuchAlgorithmException, NoSuchProviderException,
      NoSuchPaddingException, InvalidAlgorithmParameterException {

    String KSN = keySerialNumber;
    String IPEK = initialPinEncryptionKey;
    String PLAINTEXT = chdPlainData;

    byte[] pekRight = DUKPTUtil.calculateBasePinEncryptionKey(StringUtil.hexStringToBytes(IPEK),
        StringUtil.hexStringToBytes(KSN));

    byte[] ipek_variant = ByteArrayUtil.xor(StringUtil.hexStringToBytes(IPEK), StringUtil
        .hexStringToBytes(DUKPTUtil.BDK_MASK));

    byte[] pekLeft = DUKPTUtil.calculateBasePinEncryptionKey(ipek_variant, StringUtil
        .hexStringToBytes(KSN));

    byte[] pek = ByteArrayUtil.join(pekLeft, pekRight);
    System.out.println("PIN Encryption Key : " + Hex.encodeHexString(pek).toUpperCase());

    byte[] pekWithDataVariant = DUKPTUtil.calculatePinEncryptionKeyWithVariant(pek);
    System.out.println("PEK with Data Variant : "
        + Hex.encodeHexString(pekWithDataVariant).toUpperCase());

    byte[] CIPHERTEXT = DESCryptoUtil.tdesEncrypt(StringUtil.hexStringToBytes(PLAINTEXT),
        pekWithDataVariant);
    System.out.println("Encrypted Data with PEK with Data Variant : "
        + Hex.encodeHexString(CIPHERTEXT).toUpperCase());

    return Hex.encodeHexString(CIPHERTEXT).toUpperCase();

  }
}
