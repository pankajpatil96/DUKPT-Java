package dukpt.model;

public class PaymentData {

	private byte[] KSN;
	private byte[] encryptedData;
	private String cardNumberLast4Digits;
	private String cardHolderName;
	private String cardExpiration;
	
	public PaymentData(byte[] KSN, byte[] encryptedData, String cardNumberLast4Digits, String cardHolderName, String cardExpiration) {
		this.KSN = KSN;
		this.encryptedData = encryptedData;
		this.cardNumberLast4Digits = cardNumberLast4Digits;
		this.cardHolderName = cardHolderName;
		this.cardExpiration = cardExpiration;
	}

	public byte[] getKSN() {
		return KSN;
	}

	public byte[] getEncryptedData() {
		return encryptedData;
	}

	public String getCardNumberLast4Digits() {
		return cardNumberLast4Digits;
	}

	public String getCardHolderName() {
		return cardHolderName;
	}

	public String getCardExpiration() {
		return cardExpiration;
	}

}