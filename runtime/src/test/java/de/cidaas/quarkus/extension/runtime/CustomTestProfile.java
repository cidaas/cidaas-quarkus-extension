package de.cidaas.quarkus.extension.runtime;

import java.util.Map;

import io.quarkus.test.junit.QuarkusTestProfile;

public class CustomTestProfile implements QuarkusTestProfile {
	@Override
	public Map<String, String> getConfigOverrides() {
		return Map.of(
				"de.cidaas.quarkus.extension.runtime.CidaasClient/mp-rest/url", "https://mock.example.com",
				"de.cidaas.quarkus.extension.client-id", "test-client",
				"de.cidaas.quarkus.extension.client-secret", "test-secret",
				"de.cidaas.quarkus.extension.dpop-validation-mode", "off",
				"de.cidaas.quarkus.extension.mtls-validation-mode", "off",
				"de.cidaas.quarkus.extension.access-token-type-validation-mode", "off");
	}
}
