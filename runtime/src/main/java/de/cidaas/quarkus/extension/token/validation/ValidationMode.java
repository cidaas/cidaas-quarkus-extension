package de.cidaas.quarkus.extension.token.validation;

public enum ValidationMode {
	STRICT,
	REPORT,
	OFF;

	public static ValidationMode from(String value) {
		if (value == null || value.isBlank()) {
			return REPORT;
		}
		return switch (value.trim().toLowerCase()) {
		case "strict" -> STRICT;
		case "off" -> OFF;
		default -> REPORT;
		};
	}
}
