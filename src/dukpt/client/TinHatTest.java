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

  static String encryptedTerminalMasterKey = "e2711568ced0d718b53354cb0097d46f622a63276b90ae7e";
  static String encryptedInitialPinEncryptionKey = "49e32437d91232c5eecda9a6862946e5";

  static String initialKeySerialNumber = "FFFF2222223117600000";
  static String keySerialNumber = "FFFF2222223117600001";
  // static String chdPlainData = "486F77446F657333646573576F726B3F0000000000000000";
  static String chdPlainData = "5A0847617390010100369F1F1231313834343839303039313430303030303057114761739001010036D22122011184491489800000000000";

  public static void main(String[] args) throws InvalidKeyException, IllegalBlockSizeException,
      BadPaddingException, NoSuchAlgorithmException, NoSuchProviderException,
      NoSuchPaddingException, InvalidAlgorithmParameterException {
    String localKeyEncryptionKey = StringUtil.toHexString(DESCryptoUtil.tdesEncrypt(StringUtil
        .hexStringToBytes(scadIdentifier), StringUtil.hexStringToBytes(keyEncryptionKey)));

    System.out.println("LocalKeyEncryptionKey (LKEK): " + localKeyEncryptionKey);

    String terminalMasterKey = StringUtil.toHexString(DESCryptoUtil.tdesDecrypt(StringUtil
        .hexStringToBytes(encryptedTerminalMasterKey), StringUtil
        .hexStringToBytes(localKeyEncryptionKey)));

    System.out.println("TerminalMasterKey (TMK): " + terminalMasterKey);

    String initialPinEncryptionKey = StringUtil.toHexString(DESCryptoUtil.tdesDecrypt(StringUtil
        .hexStringToBytes(encryptedInitialPinEncryptionKey), StringUtil
        .hexStringToBytes(terminalMasterKey)));

    System.out.println("InitialPinEncryptionKey (IPEK): " + initialPinEncryptionKey);

    TestDukpt testDukpt = new TestDukpt();

    System.out.println("\nPlain Data: " + chdPlainData);
    System.out.println("\nEncrypted Data : "
        + testDukpt.dukptEncryption(keySerialNumber, initialPinEncryptionKey, chdPlainData));

    System.out.println("\nDecrypted Data : "
        + testDukpt.dukptDecryption(keySerialNumber, initialPinEncryptionKey, testDukpt
            .dukptEncryption(keySerialNumber, initialPinEncryptionKey, chdPlainData)));
  }
}
