package dukpt.model;

public class BankCard {

	private String cardNumber;
	private String cardHolderName;
	private String cardExpiration;
	
	public BankCard(String cardNumber, String holderName, String expirationDate) {
		this.cardNumber = cardNumber;
		this.cardHolderName = holderName;
		this.cardExpiration = expirationDate;
	}
	
	public String getCardNumber() {
		return cardNumber;
	}
	
	public String getRedactedCardNumber() {
		String displayableCardNumber = "";
		for(int i = 0; i < cardNumber.length() - 4; i++) {
			if(!cardNumber.substring(i, i + 1).equals(" ")) {
				displayableCardNumber += "*";
			}
		}
		return displayableCardNumber + cardNumber.substring(cardNumber.length() -4, cardNumber.length());
	}
	
	public String getHolderName() {
		return cardHolderName;
	}

	public String getExpirationDate() {
		return cardExpiration;
	}
	
	public String toString() {
		return "Card no.: " + cardNumber + "\nCard holder: " + getHolderName() + "\nExpiration date: " + getExpirationDate();
	}
}