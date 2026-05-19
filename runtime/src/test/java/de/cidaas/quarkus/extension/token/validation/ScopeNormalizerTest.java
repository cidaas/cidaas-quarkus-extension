package de.cidaas.quarkus.extension.token.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.List;

import org.junit.jupiter.api.Test;

class ScopeNormalizerTest {

	@Test
	void prefersRfcScopeString() {
		List<String> scopes = ScopeNormalizer.normalizeEffectiveScopes("openid profile", List.of("legacy"));
		assertEquals(List.of("openid", "profile"), scopes);
	}

	@Test
	void fallsBackToLegacyArray() {
		assertEquals(List.of("a", "b"), ScopeNormalizer.normalizeEffectiveScopes("", List.of("a", "b")));
	}

	@Test
	void returnsEmptyWhenNeitherClaimPresent() {
		assertEquals(List.of(), ScopeNormalizer.normalizeEffectiveScopes("  ", List.of()));
	}

	@Test
	void returnsEmptyWhenBothClaimsAbsent() {
		assertEquals(List.of(), ScopeNormalizer.normalizeEffectiveScopes(null, null));
	}
}
