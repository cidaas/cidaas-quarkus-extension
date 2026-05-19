package de.cidaas.quarkus.extension.token.validation;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Merges OAuth {@code scope} (space-separated string) and legacy {@code scopes} array claims.
 */
public final class ScopeNormalizer {

	private ScopeNormalizer() {
	}

	public static List<String> normalizeEffectiveScopes(String scopeClaim, List<String> legacyScopes) {
		if (scopeClaim != null && !scopeClaim.isBlank()) {
			return Arrays.asList(scopeClaim.trim().split("\\s+"));
		}
		if (legacyScopes != null && !legacyScopes.isEmpty()) {
			return legacyScopes;
		}
		return Collections.emptyList();
	}
}
