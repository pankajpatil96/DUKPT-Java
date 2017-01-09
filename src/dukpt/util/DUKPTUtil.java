package dukpt.util;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class DUKPTUtil {
  // When AND'ed to a 10 byte KSN, zeroes all the 21 bits of the transaction
  // counter
  public static final String KSN_MASK = "FF FF FF FF FF FF FF E0 00 00";
  // When AND'ed to a 10 byte KSN, zeroes all 59 most significative bits,
  // preserving only the 21 bits of the transaction counter
  public static final String TRANSACTION_COUNTER_MASK = "00 00 00 00 00 00 00 1F FF FF";
  // Used for deriving IPEK and future keys
  public static final String BDK_MASK = "C0 C0 C0 C0 00 00 00 00 C0 C0 C0 C0 00 00 00 00";
  // private static final String PIN_ENCRYPTION_VARIANT_CONSTANT = "00 00 00 00 00 00 00 FF"; // OLD
  private static final String PIN_ENCRYPTION_VARIANT_CONSTANT = "00 00 00 00 00 FF 00 00 ";

  private static final String SHIFTR = "00 00 00 00 00 10 00 00";

  private static final String KSN_MODIFIER_MASK = "00 00 FF FF FF FF FF FF FF FF";

  /**
   * Generates an IPEK
   * 
   * @param KSN
   *          10 bytes array (if your SNK has less than 10 bytes, pad it with 0xFF bytes to the
   *          left).
   * @param BDK
   *          24 bytes array. It's a triple-key (mandatory for TDES), and each key has 8 bytes. In
   *          DUKPT, double-keys are uses, so K1 = K3 (ex. K1 = 01 23 45 67 89 AB CD EF, K2 = FE DC
   *          BA 98 76 54 32 10, K3 = K1 = 01 23 45 67 89 AB CD EF)
   * @return a 16 byte IPEK for a specific device (the one associated with the serial key number in
   *         KSN), containing both the serial number and the ID of the associated BDK The BDK format
   *         is usually like follows: FF FF | BDK_ID[6] | TRSM_SN[5] | COUNTER[5] Note that the
   *         rightmost bit of TRSM_ID must not be used, for it belongs to the COUNTER. So the bytes
   *         of TRSM_SN must always form a multiple of 2 value
   * @throws InvalidAlgorithmParameterException
   * @throws NoSuchPaddingException
   * @throws NoSuchProviderException
   * @throws NoSuchAlgorithmException
   * @throws BadPaddingException
   * @throws IllegalBlockSizeException
   * @throws InvalidKeyException
   */
  public static byte[] generateIPEK(byte[] KSN, byte[] BDK)
      throws InvalidKeyException, IllegalBlockSizeException,
      BadPaddingException, NoSuchAlgorithmException,
      NoSuchProviderException, NoSuchPaddingException,
      InvalidAlgorithmParameterException {
    // 1) Copy the entire key serial number, including the 21-bit encryption counter,
    // right-justified into a 10-byte register. If the key serial
    // number is less than 10 bytes, pad to the left with hex "FF" bytes.

    // 2) Set the 21 least-significant bits of this 10-byte register to zero.
    byte[] KSN_mask = StringUtil.hexStringToBytes(KSN_MASK);
    byte[] masked_KSN = ByteArrayUtil.and(KSN, KSN_mask);

    // 3) Take the 8 most-significant bytes of this 10-byte register, and encrypt/decrypt/encrypt
    // these 8 bytes using the double-length
    // derivation key, per the TECB mode of Reference 2.
    byte[] eigth_byte_masked_KSN = new byte[8];
    for (int i = 0; i < 8; i++) {
      eigth_byte_masked_KSN[i] = masked_KSN[i];
    }

    byte[] IPEK_left = DESCryptoUtil.tdesEncrypt(eigth_byte_masked_KSN, BDK);

    // 4) Use the cipher text produced by Step 3 as the left half of the
    // Initial Key.
    byte[] IPEK = new byte[16];
    for (int i = 0; i < 8; i++) {
      IPEK[i] = IPEK_left[i];
    }

    // 5) Take the 8 most-significant bytes from the 10-byte register of step 2 and
    // encrypt/decrypt/encrypt these 8 bytes using as the key the
    // double-length derivation key XORed with hexadecimal C0C0 C0C0 0000 0000 C0C0 C0C0 0000 0000,
    // per the TECB mode of Reference 2.
    byte[] derivation_mask = StringUtil.hexStringToBytes(BDK_MASK);
    byte[] masked_derivation_key = ByteArrayUtil.xor(BDK, derivation_mask);
    byte[] IPEK_right = DESCryptoUtil.tdesEncrypt(eigth_byte_masked_KSN, masked_derivation_key);

    // 6) Use the cipher text produced by Step 5 as the right half of the Initial Key.
    for (int i = 0; i < 8; i++) {
      IPEK[i + 8] = IPEK_right[i];
    }

    return IPEK;
  }

  /**
   * @param ksn
   *          ten byte array, which 2 leftmost bytes value is 0xFF (ex. FF FF 98 76 54 32 10 E0 12
   *          34)
   * @return the ksn with it's last 21 bits set to 0. (ex. FF FF 98 76 54 32 10 E0 00 00)
   */
  public static byte[] ksnWithZeroedTransactionCounter(byte[] ksn) {
    return ByteArrayUtil.and(ksn, StringUtil.hexStringToBytes(KSN_MASK));
  }

  /**
   * @param ksn
   *          ten byte array, which 2 leftmost bytes value is 0xFF (ex. FF FF 98 76 54 32 10 E0 12
   *          34)
   * @return the value of the ksnl's last 21 bits, right justified and padded to left with zeroes,
   *         as a 8 byte array (ex. 00 00 00 00 00 00 00 00 12 34)
   */
  public static byte[] extractTransactionCounterFromKSN(byte[] ksn) {
    return ByteArrayUtil.subArray(
        ByteArrayUtil.and(ksn,
            StringUtil.hexStringToBytes(TRANSACTION_COUNTER_MASK)),
        2, 9);
  }

  /**
   * Given a Base Derivation Key and a KSN, derives Session Key that matches the encryption counter
   * (21 rightmost bits of the KSN)
   * 
   * @param ksn
   *          ten byte array, which 2 leftmost bytes value is 0xFF (ex. FF FF 98 76 54 32 10 E0 12
   *          34)
   * @param bdk
   *          16 bytes array (double-length key)
   * @return
   * @throws InvalidKeyException
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   * @throws NoSuchAlgorithmException
   * @throws NoSuchProviderException
   * @throws NoSuchPaddingException
   * @throws InvalidAlgorithmParameterException
   */
  public static byte[] deriveKey(byte[] ksn, byte[] bdk)
      throws InvalidKeyException, IllegalBlockSizeException,
      BadPaddingException, NoSuchAlgorithmException,
      NoSuchProviderException, NoSuchPaddingException,
      InvalidAlgorithmParameterException {
    // 4) Store the Key Serial Number, as received, in the externally
    // initiated command, into the Key Serial Number Register.
    // 5) Clear the encryption counter (21st right-most bits of KSNR
    byte[] r3 = DUKPTUtil.extractTransactionCounterFromKSN(ksn);
    byte[] r8 = ByteArrayUtil.subArray(
        DUKPTUtil.ksnWithZeroedTransactionCounter(ksn), 2, 9);
    byte[] shiftr = StringUtil.hexStringToBytes(SHIFTR);
    byte[] crypto_register_1 = ByteArrayUtil.subArray(
        DUKPTUtil.ksnWithZeroedTransactionCounter(ksn), 2, 9);
    byte[] curKey = bdk;

    curKey = DUKPTUtil.generateIPEK(ksn, curKey);

    BigInteger intShiftr = new BigInteger(shiftr);
    BigInteger zero = new BigInteger("0");

    while (intShiftr.compareTo(zero) == 1) {
      byte[] temp = ByteArrayUtil.and(shiftr, r3);
      BigInteger intTemp = new BigInteger(temp);

      if (intTemp.compareTo(zero) == 1) {
        r8 = ByteArrayUtil.or(r8, shiftr);
        // crypto_register_1 =
        // ByteArrayUtil.or(ByteArrayUtil.createSubArray(DUKPTUtil.ksnWithZeroedTransactionCounter(ksn),
        // 2, 9)/*crypto_register_1*/, shiftr);

        // 1) Crypto Register-1 XORed with the right half of the Key
        // Register goes to Crypto Register-2.
        byte[] crypto_register_2 = ByteArrayUtil.xor(
            r8/* crypto_register_1 */,
            ByteArrayUtil.subArray(curKey, 8, 15));

        // 2) Crypto Register-2 DEA-encrypted using, as the key, the
        // left half of the Key Register goes to Crypto Register-2.
        crypto_register_2 = DESCryptoUtil.desEncrypt(crypto_register_2,
            ByteArrayUtil.subArray(curKey, 0, 7));

        // 3) Crypto Register-2 XORed with the right half of the Key
        // Register goes to Crypto Register-2.
        crypto_register_2 = ByteArrayUtil.xor(crypto_register_2,
            ByteArrayUtil.subArray(curKey, 8, 15));

        // 4) XOR the Key Register with hexadecimal C0C0 C0C0 0000 0000
        // C0C0 C0C0 0000 0000.
        curKey = ByteArrayUtil.xor(curKey,
            StringUtil.hexStringToBytes(BDK_MASK));

        // 5) Crypto Register-1 XORed with the right half of the Key
        // Register goes to Crypto Register-1.
        crypto_register_1 = ByteArrayUtil.xor(
            r8/* crypto_register_1 */,
            ByteArrayUtil.subArray(curKey, 8, 15));

        // 6) Crypto Register-1 DEA-encrypted using, as the key, the
        // left half of the Key Register goes to Crypto Register-1.
        crypto_register_1 = DESCryptoUtil.desEncrypt(crypto_register_1,
            ByteArrayUtil.subArray(curKey, 0, 7));

        // 7) Crypto Register-1 XORed with the right half of the Key
        // Register goes to Crypto Register-1.
        crypto_register_1 = ByteArrayUtil.xor(crypto_register_1,
            ByteArrayUtil.subArray(curKey, 8, 15));

        curKey = ByteArrayUtil.join(crypto_register_1,
            crypto_register_2);
      }

      shiftr = ByteArrayUtil.shiftRight(shiftr, 1);
      intShiftr = new BigInteger(shiftr);
    }

    return curKey;
  }

  // public static byte[] calculateDataEncryptionKey(byte[] key) throws InvalidKeyException,
  // IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException,
  // NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException {
  // byte[] derived_key = key;
  // byte[] derived_key_L = ByteArrayUtil.createSubArray(derived_key, 0, 7);
  // byte[] derived_key_R = ByteArrayUtil.createSubArray(derived_key, 8, 15);
  // byte[] data_encryption_variant_constant_both_ways =
  // StringUtil.hexStringToBytes(DATA_ENCRYPTION_VARIANT_CONSTANT_BOTH_WAYS);
  //
  // // 1 - derived_key_L XOR'ed with DATA_ENCRYPTION_VARIANT_CONSTANT_BOTH_WAYS = variant_key_L
  // byte[] variant_key_L = ByteArrayUtil.xor(derived_key_L,
  // data_encryption_variant_constant_both_ways);
  //
  // // 2 - derived_key_R XOR'ed with DATA_ENCRYPTION_VARIANT_CONSTANT_BOTH_WAYS = variant_key_R
  // byte[] variant_key_R = ByteArrayUtil.xor(derived_key_R,
  // data_encryption_variant_constant_both_ways);
  //
  // // 3 - variant_key_L << 64 & variant_key_R = variant_key_L_R byte[] variant_key_L_R =
  // ByteArrayUtil.joinArrays(variant_key_L, variant_key_R);
  //
  // // 4 - TDEA variantkley_L with variant_key_L_R = encryption_key_L byte[] encryption_key_L =
  // DESCryptoUtil.tdesEncrypt(variant_key_L, variant_key_L_R);
  //
  // // 5 - TDEA variant_key_R with variant_key_L_R = encryption_key_R byte[] encryption_key_R =
  // DESCryptoUtil.tdesEncrypt(variant_key_R, variant_key_L_R);
  //
  // // 6 - variant_key_L << 64 & variant_key_R = new_derived_data_key byte[] new_derived_data_key =
  // ByteArrayUtil.joinArrays(encryption_key_L, encryption_key_R);
  //
  // return new_derived_data_key;
  // }

  /**
   * 
   * @param derivedKey
   *          result of {@link #deriveKey(byte[], byte[])} to generate the key used to encrypt card
   *          track info.
   * @return 16 byte array key that should be passed as the second parameter of
   *         {@link DESCryptoUtil#tdesDecrypt(byte[], byte[])}
   * @throws InvalidAlgorithmParameterException
   * @throws NoSuchPaddingException
   * @throws NoSuchProviderException
   * @throws NoSuchAlgorithmException
   * @throws BadPaddingException
   * @throws IllegalBlockSizeException
   * @throws InvalidKeyException
   */
  public static byte[] calculateBasePinEncryptionKey(byte[] derivedKey, byte[] ksn)
      throws InvalidKeyException,
      IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException,
      NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException {
    byte[] derivedKeyL = ByteArrayUtil.subArray(derivedKey, 0, 7);
    byte[] derivedKeyR = ByteArrayUtil.subArray(derivedKey, 8, 15);
    byte[] KSN_Mod_Mask = StringUtil.hexStringToBytes(KSN_MODIFIER_MASK);
    byte[] ksnMod = ByteArrayUtil.subArray(ByteArrayUtil.and(ksn, KSN_Mod_Mask), 2, 9);

    byte[] pin_encryption_key_part = ByteArrayUtil.xor(derivedKeyR, ksnMod);

    byte[] encryptedMessage = DESCryptoUtil.desEncrypt(pin_encryption_key_part, derivedKeyL);
    pin_encryption_key_part = ByteArrayUtil.xor(derivedKeyR, encryptedMessage);
    return pin_encryption_key_part;
  }

  /**
   * 
   * @param derivedKey
   *          result of {@link #deriveKey(byte[], byte[])} to generate the key used to encrypt card
   *          track info.
   * @return 16 byte array key that should be passed as the second parameter of
   *         {@link DESCryptoUtil#tdesDecrypt(byte[], byte[])}
   * @throws InvalidAlgorithmParameterException
   * @throws NoSuchPaddingException
   * @throws NoSuchProviderException
   * @throws NoSuchAlgorithmException
   * @throws BadPaddingException
   * @throws IllegalBlockSizeException
   * @throws InvalidKeyException
   */
  public static byte[] calculatePinEncryptionKeyWithNoVariant(byte[] derivedKey)
      throws InvalidKeyException,
      IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException,
      NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException {
    byte[] variant_constant = StringUtil.hexStringToBytes(PIN_ENCRYPTION_VARIANT_CONSTANT);
    byte[] derivedKeyL = ByteArrayUtil.subArray(derivedKey, 0, 7);
    byte[] derivedKeyR = ByteArrayUtil.subArray(derivedKey, 8, 15);

    // 1 - derivedKey_L XOR pin_variant_constant = pin_key_L
    byte[] pin_key_L = ByteArrayUtil.xor(derivedKeyL, variant_constant);
    // System.out.println(Hex.encodeHexString(pin_key_L));
    // 2 - derivedKey_R XOR pin_variant_constant_R = pin_key_R
    byte[] pin_key_R = ByteArrayUtil.xor(derivedKeyR, variant_constant);
    // System.out.println(Hex.encodeHexString(pin_key_R));

    byte[] pekVariantL = DESCryptoUtil.tdesEncrypt(pin_key_L, ByteArrayUtil.join(pin_key_L,
        pin_key_R));
    // System.out.println(Hex.encodeHexString(pekVariantL));

    byte[] pekVariantR = DESCryptoUtil.tdesEncrypt(pin_key_R, ByteArrayUtil.join(pin_key_L,
        pin_key_R));
    // System.out.println(Hex.encodeHexString(pekVariantR));

    return ByteArrayUtil.join(pin_key_L, pin_key_R);
  }

  /**
   * 
   * @param derivedKey
   *          result of {@link #deriveKey(byte[], byte[])} to generate the key used to encrypt card
   *          track info.
   * @return 16 byte array key that should be passed as the second parameter of
   *         {@link DESCryptoUtil#tdesDecrypt(byte[], byte[])}
   * @throws InvalidAlgorithmParameterException
   * @throws NoSuchPaddingException
   * @throws NoSuchProviderException
   * @throws NoSuchAlgorithmException
   * @throws BadPaddingException
   * @throws IllegalBlockSizeException
   * @throws InvalidKeyException
   */
  public static byte[] calculatePinEncryptionKeyWithVariant(byte[] derivedKey)
      throws InvalidKeyException,
      IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException,
      NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException {
    byte[] variant_constant = StringUtil.hexStringToBytes(PIN_ENCRYPTION_VARIANT_CONSTANT);
    byte[] derivedKeyL = ByteArrayUtil.subArray(derivedKey, 0, 7);
    byte[] derivedKeyR = ByteArrayUtil.subArray(derivedKey, 8, 15);

    // 1 - derivedKey_L XOR pin_variant_constant = pin_key_L
    byte[] pin_key_L = ByteArrayUtil.xor(derivedKeyL, variant_constant);
    // System.out.println(Hex.encodeHexString(pin_key_L));
    // 2 - derivedKey_R XOR pin_variant_constant_R = pin_key_R
    byte[] pin_key_R = ByteArrayUtil.xor(derivedKeyR, variant_constant);
    // System.out.println(Hex.encodeHexString(pin_key_R));

    byte[] pekVariantL = DESCryptoUtil.tdesEncrypt(pin_key_L, ByteArrayUtil.join(pin_key_L,
        pin_key_R));
    // System.out.println(Hex.encodeHexString(pekVariantL));

    byte[] pekVariantR = DESCryptoUtil.tdesEncrypt(pin_key_R, ByteArrayUtil.join(pin_key_L,
        pin_key_R));
    // System.out.println(Hex.encodeHexString(pekVariantR));

    return ByteArrayUtil.join(pekVariantL, pekVariantR);
  }

  public static byte[] decryptTrack1(byte[] track1, byte[] KSN, byte[] BDK) {
    try {
      byte[] derivedKey = deriveKey(KSN, BDK);
      byte[] pinKey = calculatePinEncryptionKeyWithNoVariant(derivedKey);
      byte[] decryptedInfo = DESCryptoUtil.tdesDecrypt(track1, pinKey);
      return decryptedInfo;
    } catch (Exception e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
      System.out.println(e.getMessage());
      System.out.flush();
      return null;
    }
  }
}
