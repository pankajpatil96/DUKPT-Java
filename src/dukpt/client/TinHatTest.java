package dukpt.client;

import dukpt.util.DESCryptoUtil;
import dukpt.util.StringUtil;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class TinHatTest {

  static String keyEncryptionKey = "747419ab84c284c3a682455fe1f17e5179c1e8fdde32ed42";
  static String scadIdentifier = "000102030405060708090A0B0C0D0E0F1011121314151617";

  public static void main(String[] args) throws InvalidKeyException, IllegalBlockSizeException,
      BadPaddingException, NoSuchAlgorithmException, NoSuchProviderException,
      NoSuchPaddingException, InvalidAlgorithmParameterException {
    String localKeyEncryptionKey = StringUtil.toHexString(DESCryptoUtil.tdesEncrypt(StringUtil
        .hexStringToBytes(scadIdentifier), StringUtil.hexStringToBytes(keyEncryptionKey)));

    System.out.println(localKeyEncryptionKey);
  }
}
