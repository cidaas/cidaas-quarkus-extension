package de.cidaas.quarkus.extension.token.validation;

public class ValidationResult {
	private final boolean valid;
	private final TokenData tokenData;

	public ValidationResult(boolean valid, TokenData tokenData) {
		this.valid = valid;
		this.tokenData = tokenData;
	}

	public static ValidationResult invalid() {
		return new ValidationResult(false, null);
	}

	public static ValidationResult valid(TokenData tokenData) {
		return new ValidationResult(true, tokenData);
	}

	public boolean isValid() {
		return valid;
	}

	public TokenData getTokenData() {
		return tokenData;
	}
}
