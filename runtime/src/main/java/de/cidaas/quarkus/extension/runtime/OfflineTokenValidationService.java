package de.cidaas.quarkus.extension.runtime;

import java.time.Instant;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.cidaas.quarkus.extension.token.validation.ClaimValidator;
import de.cidaas.quarkus.extension.token.validation.JwtClaimsReader;
import de.cidaas.quarkus.extension.token.validation.JwtUtil;
import de.cidaas.quarkus.extension.token.validation.TokenValidationException;
import de.cidaas.quarkus.extension.token.validation.TokenValidationRequest;
import de.cidaas.quarkus.extension.token.validation.ValidationMode;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;

@ApplicationScoped
public class OfflineTokenValidationService {

	@Inject
	CidaasInstanceService instanceService;

	@Inject
	NimbusJwtSignatureVerifier signatureVerifier;

	private static final Logger LOG = LoggerFactory.getLogger(OfflineTokenValidationService.class);

	public boolean validateToken(TokenValidationRequest tokenValidationRequest) {
		return validateToken(tokenValidationRequest, instanceService.defaultBaseUrl(), ValidationMode.OFF);
	}

	public boolean validateToken(TokenValidationRequest tokenValidationRequest, String baseUrl,
			ValidationMode accessTokenTypeMode) {
		String token = tokenValidationRequest.getToken();
		JsonObject header = JwtUtil.decodeHeader(token);
		if (header == null || !validateTokenHeader(header, baseUrl)) {
			return false;
		}
		if (!validateAccessTokenType(header, accessTokenTypeMode)) {
			return false;
		}
		JsonObject payload = JwtUtil.decodePayload(token);
		if (payload == null || !validateGeneralInfo(payload, baseUrl)) {
			return false;
		}
		if (!signatureVerifier.validateTokenSignature(token, baseUrl)) {
			return false;
		}
		return ClaimValidator.validate(tokenValidationRequest, JwtClaimsReader.readScopes(payload),
				JwtClaimsReader.readRoles(payload), JwtClaimsReader.readGroups(payload));
	}

	public boolean validateAccessTokenType(JsonObject header, ValidationMode mode) {
		if (mode == ValidationMode.OFF) {
			return true;
		}
		String typ = header.getString("typ", "");
		boolean valid = "at+jwt".equals(typ);
		if (!valid && mode == ValidationMode.STRICT) {
			LOG.warn("access token missing typ at+jwt, got {}", typ);
		}
		return valid || mode == ValidationMode.REPORT;
	}

	public boolean validateTokenHeader(JsonObject header, String baseUrl) {
		JsonObject jwks = instanceService.getJwks(baseUrl);
		if (jwks == null) {
			throw new TokenValidationException("JWK invalid!");
		}
		JsonArray keys = jwks.getJsonArray("keys");
		if (keys == null || keys.isEmpty()) {
			throw new TokenValidationException("JWK invalid!");
		}
		String kid = header.getString("kid", null);
		String alg = header.getString("alg", null);
		if (kid == null || alg == null) {
			return false;
		}
		for (int i = 0; i < keys.size(); i++) {
			JsonObject key = keys.getJsonObject(i);
			if (kid.equals(key.getString("kid", "")) && alg.equals(key.getString("alg", ""))) {
				return true;
			}
		}
		return false;
	}

	public boolean validateGeneralInfo(JsonObject payload, String baseUrl) {
		String iss = payload.getString("iss", null);
		if (iss == null || !iss.equals(baseUrl)) {
			LOG.warn("iss is invalid!");
			return false;
		}
		if (!payload.containsKey("exp")) {
			return false;
		}
		int exp = payload.getInt("exp");
		if (Instant.ofEpochSecond(exp).isBefore(Instant.now())) {
			LOG.warn("token is expired!");
			return false;
		}
		return true;
	}
}
