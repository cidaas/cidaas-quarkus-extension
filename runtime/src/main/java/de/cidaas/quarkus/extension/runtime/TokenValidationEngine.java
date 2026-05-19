package de.cidaas.quarkus.extension.runtime;

import java.time.Instant;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.cidaas.quarkus.extension.token.validation.ClientIdResolver;
import de.cidaas.quarkus.extension.token.validation.IntrospectResponse;
import de.cidaas.quarkus.extension.token.validation.JwtClaimsReader;
import de.cidaas.quarkus.extension.token.validation.JwtUtil;
import de.cidaas.quarkus.extension.token.validation.TokenData;
import de.cidaas.quarkus.extension.token.validation.TokenValidationException;
import de.cidaas.quarkus.extension.token.validation.TokenValidationRequest;
import de.cidaas.quarkus.extension.token.validation.ValidationMode;
import de.cidaas.quarkus.extension.token.validation.ValidationResult;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.json.JsonObject;

@ApplicationScoped
public class TokenValidationEngine {

	private static final Logger LOG = LoggerFactory.getLogger(TokenValidationEngine.class);

	@Inject
	CidaasHttpClient httpClient;

	@Inject
	CidaasInstanceService instanceService;

	@Inject
	OfflineTokenValidationService offlineTokenValidationService;

	@Inject
	DPoPValidator dpopValidator;

	@Inject
	CidaasExtensionConfig config;

	public ValidationResult validate(TokenValidationRequest request, CidaasRequestMetadata metadata,
			String customBaseUrl, boolean offline, ValidationMode dpopMode, ValidationMode mtlsMode,
			ValidationMode accessTokenTypeMode) {
		String baseUrl = resolveBaseUrl(metadata, customBaseUrl);
		if (baseUrl == null || baseUrl.isBlank()) {
			LOG.warn("No cidaas base URL configured");
			return ValidationResult.invalid();
		}
		if (offline) {
			return validateOffline(request, metadata, baseUrl, dpopMode, mtlsMode, accessTokenTypeMode);
		}
		return validateIntrospect(request, metadata, baseUrl, dpopMode, mtlsMode);
	}

	private ValidationResult validateIntrospect(TokenValidationRequest request, CidaasRequestMetadata metadata,
			String baseUrl, ValidationMode dpopMode, ValidationMode mtlsMode) {
		return validateIntrospectWithEndpoint(request, metadata, baseUrl, null, dpopMode, mtlsMode);
	}

	private ValidationResult validateOffline(TokenValidationRequest request, CidaasRequestMetadata metadata,
			String baseUrl, ValidationMode dpopMode, ValidationMode mtlsMode,
			ValidationMode accessTokenTypeMode) {
		if (!offlineTokenValidationService.validateToken(request, baseUrl, accessTokenTypeMode)) {
			return ValidationResult.invalid();
		}
		JsonObject payload = JwtUtil.decodePayload(request.getToken());
		if (payload == null) {
			return ValidationResult.invalid();
		}
		List<String> scopes = JwtClaimsReader.readScopes(payload);
		List<String> roles = JwtClaimsReader.readRoles(payload);
		List<de.cidaas.quarkus.extension.token.validation.GroupDetails> groups = JwtClaimsReader.readGroups(payload);
		TokenData tokenData = new TokenData();
		tokenData.setSub(payload.getString("sub", ""));
		tokenData.setAud(JwtClaimsReader.readAudience(payload));
		tokenData.setScopes(scopes);
		tokenData.setGroups(groups);
		tokenData.setClientId(ClientIdResolver.resolve(payload.getString("client_id", ""), tokenData.getAud()));

		String jkt = JwtClaimsReader.readCnfJkt(payload);
		if (!dpopValidator.validate(metadata, request.getToken(), jkt, dpopMode)) {
			return ValidationResult.invalid();
		}
		String x5t = JwtClaimsReader.readCnfX5tS256(payload);
		if (!MtlsBindingValidator.validate(metadata, x5t, mtlsMode)) {
			return ValidationResult.invalid();
		}
		return ValidationResult.valid(tokenData);
	}

	public ValidationResult validatePat(TokenValidationRequest request, CidaasRequestMetadata metadata,
			String customBaseUrl) {
		String baseUrl = resolveBaseUrl(metadata, customBaseUrl);
		if (baseUrl == null || baseUrl.isBlank()) {
			return ValidationResult.invalid();
		}
		String patEndpoint = baseUrl.replaceAll("/$", "") + "/accesspass-srv/passes/pat/introspect";
		request.setToken_type_hint("pat");
		return validateIntrospectWithEndpoint(request, metadata, baseUrl, patEndpoint, ValidationMode.OFF,
				ValidationMode.OFF);
	}

	private ValidationResult validateIntrospectWithEndpoint(TokenValidationRequest request,
			CidaasRequestMetadata metadata, String baseUrl, String introspectionEndpoint, ValidationMode dpopMode,
			ValidationMode mtlsMode) {
		try {
			IntrospectResponse response = httpClient.introspect(baseUrl, request, metadata, introspectionEndpoint);
			if (!response.isActive()) {
				return ValidationResult.invalid();
			}
			String expectedIss = instanceService.getInstanceDetails(baseUrl).getIssuer();
			if (!issuerMatches(expectedIss, response.getIss())) {
				return ValidationResult.invalid();
			}
			TokenData tokenData = response.toTokenData();
			String jkt = response.getCnf().getOrDefault("jkt", "");
			if (!dpopValidator.validate(metadata, request.getToken(), jkt, dpopMode)) {
				return ValidationResult.invalid();
			}
			String x5t = response.getCnf().getOrDefault("x5t#S256", "");
			if (!MtlsBindingValidator.validate(metadata, x5t, mtlsMode)) {
				return ValidationResult.invalid();
			}
			return ValidationResult.valid(tokenData);
		} catch (TokenValidationException e) {
			LOG.warn("Introspect validation failed: {}", e.getMessage());
			return ValidationResult.invalid();
		}
	}

	private String resolveBaseUrl(CidaasRequestMetadata metadata, String customBaseUrl) {
		if (customBaseUrl != null && !customBaseUrl.isBlank()) {
			return customBaseUrl;
		}
		String configured = config.baseUrl();
		if (configured != null && !configured.isBlank()) {
			return configured;
		}
		return instanceService.defaultBaseUrl();
	}

	private static boolean issuerMatches(String expected, String actual) {
		if (expected == null || actual == null) {
			return false;
		}
		return expected.equals(actual) || expected.equalsIgnoreCase(actual);
	}
}
