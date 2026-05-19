package de.cidaas.quarkus.extension.runtime;

import java.util.Base64;

import de.cidaas.quarkus.extension.token.validation.ValidationMode;

public final class MtlsBindingValidator {

	private MtlsBindingValidator() {
	}

	public static boolean validate(CidaasRequestMetadata metadata, String x5tS256, ValidationMode mode) {
		if (mode == ValidationMode.OFF || x5tS256 == null || x5tS256.isBlank()) {
			return true;
		}
		String fp = metadata.getMtlsFingerprint();
		if (fp == null || fp.isBlank()) {
			return mode != ValidationMode.STRICT;
		}
		return matchesCnfS256(fp.trim(), x5tS256.trim());
	}

	static boolean matchesCnfS256(String hexFingerprint, String x5tS256) {
		try {
			byte[] fpBytes = hexToBytes(hexFingerprint);
			byte[] claimBytes = decodeBase64UrlOrStd(x5tS256);
			if (fpBytes.length != claimBytes.length) {
				return false;
			}
			int diff = 0;
			for (int i = 0; i < fpBytes.length; i++) {
				diff |= fpBytes[i] ^ claimBytes[i];
			}
			return diff == 0;
		} catch (Exception e) {
			return false;
		}
	}

	private static byte[] hexToBytes(String hex) {
		String cleaned = hex.replace(":", "").replace(" ", "");
		int len = cleaned.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(cleaned.charAt(i), 16) << 4)
					+ Character.digit(cleaned.charAt(i + 1), 16));
		}
		return data;
	}

	private static byte[] decodeBase64UrlOrStd(String value) {
		try {
			return Base64.getUrlDecoder().decode(value);
		} catch (IllegalArgumentException e) {
			return Base64.getDecoder().decode(value);
		}
	}
}
