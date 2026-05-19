package de.cidaas.quarkus.extension.token.validation;

import java.util.List;

public final class ClientIdResolver {

	private ClientIdResolver() {
	}

	public static String resolve(String clientId, List<String> aud) {
		if (clientId != null && !clientId.isBlank()) {
			return clientId.trim();
		}
		if (aud != null && !aud.isEmpty() && aud.get(0) != null && !aud.get(0).isBlank()) {
			return aud.get(0).trim();
		}
		return "";
	}
}
