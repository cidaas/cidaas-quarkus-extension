package de.cidaas.quarkus.extension.runtime;

import de.cidaas.quarkus.extension.token.validation.TokenValidationRequest;
import de.cidaas.quarkus.extension.token.validation.ValidationMode;
import de.cidaas.quarkus.extension.token.validation.ValidationService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

@ApplicationScoped
public class CidaasService implements ValidationService {

	@Inject
	TokenValidationEngine validationEngine;

	@Inject
	CidaasExtensionConfig config;

	@Override
	public boolean validateToken(TokenValidationRequest request) {
		String baseUrl = config.baseUrl();
		if (baseUrl == null || baseUrl.isBlank()) {
			baseUrl = "https://localhost";
		}
		return validationEngine.validate(request, CidaasRequestMetadata.minimal(baseUrl, request.getToken()), "",
				false, config.dpopMode(), config.mtlsMode(), config.accessTokenTypeMode()).isValid();
	}
}
