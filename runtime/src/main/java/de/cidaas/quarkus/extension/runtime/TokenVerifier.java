package de.cidaas.quarkus.extension.runtime;

import de.cidaas.quarkus.extension.annotation.TokenValidation;
import de.cidaas.quarkus.extension.token.validation.TokenValidationMapper;
import de.cidaas.quarkus.extension.token.validation.TokenValidationRequest;
import de.cidaas.quarkus.extension.token.validation.ValidationMode;
import de.cidaas.quarkus.extension.token.validation.ValidationResult;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;

/**
 * Programmatic validation API (Go {@code verify.ByTokenRequest} equivalent).
 */
@ApplicationScoped
public class TokenVerifier {

	@Inject
	TokenValidationEngine validationEngine;

	@Inject
	CidaasExtensionConfig config;

	public ValidationResult validateByTokenRequest(String issuerUrl, String accessToken,
			TokenValidationRequest endpointOptions, ContainerRequestContext requestContext, boolean offline) {
		endpointOptions.setToken(accessToken);
		CidaasRequestMetadata metadata = requestContext != null
				? CidaasRequestMetadata.from(requestContext)
				: minimalMetadata(accessToken, issuerUrl);
		return validationEngine.validate(endpointOptions, metadata, issuerUrl, offline,
				config.dpopMode(), config.mtlsMode(), config.accessTokenTypeMode());
	}

	public ValidationResult validateByTokenRequest(String issuerUrl, String accessToken,
			TokenValidation annotation, ContainerRequestContext requestContext) {
		TokenValidationRequest request = TokenValidationMapper.mapToValidationRequest(accessToken, annotation);
		return validateByTokenRequest(issuerUrl, accessToken, request, requestContext,
				annotation.offlineValidation());
	}

	private CidaasRequestMetadata minimalMetadata(String accessToken, String issuerUrl) {
		return CidaasRequestMetadata.minimal(accessToken, issuerUrl);
	}
}
