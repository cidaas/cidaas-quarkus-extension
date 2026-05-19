package de.cidaas.quarkus.extension.runtime;

import org.eclipse.microprofile.config.ConfigProvider;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import de.cidaas.quarkus.extension.token.validation.ValidationMode;
import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class CidaasExtensionConfig {

	private static final String LEGACY_BASE_URL_KEY = "de.cidaas.quarkus.extension.runtime.CidaasClient/mp-rest/url";

	@ConfigProperty(name = "de.cidaas.quarkus.extension.base-url")
	java.util.Optional<String> baseUrl;

	@ConfigProperty(name = "de.cidaas.quarkus.extension.client-id")
	java.util.Optional<String> clientId;

	@ConfigProperty(name = "de.cidaas.quarkus.extension.client-secret")
	java.util.Optional<String> clientSecret;

	@ConfigProperty(name = "de.cidaas.quarkus.extension.dpop-validation-mode", defaultValue = "off")
	String dpopValidationMode;

	@ConfigProperty(name = "de.cidaas.quarkus.extension.mtls-validation-mode", defaultValue = "off")
	String mtlsValidationMode;

	@ConfigProperty(name = "de.cidaas.quarkus.extension.access-token-type-validation-mode", defaultValue = "report")
	String accessTokenTypeValidationMode;

	public String baseUrl() {
		return baseUrl.filter(s -> !s.isBlank())
				.orElseGet(() -> ConfigProvider.getConfig().getOptionalValue(LEGACY_BASE_URL_KEY, String.class).orElse(""));
	}

	public String clientId() {
		return clientId.orElse("");
	}

	public String clientSecret() {
		return clientSecret.orElse("");
	}

	public ValidationMode dpopMode() {
		return ValidationMode.from(dpopValidationMode);
	}

	public ValidationMode mtlsMode() {
		return ValidationMode.from(mtlsValidationMode);
	}

	public ValidationMode accessTokenTypeMode() {
		return ValidationMode.from(accessTokenTypeValidationMode);
	}
}
