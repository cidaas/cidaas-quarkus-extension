package de.cidaas.quarkus.extension.token.validation;

import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.eclipse.microprofile.config.ConfigProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;

import de.cidaas.quarkus.extension.runtime.CacheService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonString;

@ApplicationScoped
public class OfflineTokenValidationService implements ValidationService {
	@Inject
	CacheService cacheService;

	private static final Logger LOG = LoggerFactory.getLogger(OfflineTokenValidationService.class);

	/**
	 * validate token without calling introspection endpoint.
	 *
	 * @param tokenValidationRequest contain access token and definition which claims
	 *                               to be validated and how.
	 * 
	 * @return true if tokenValidationRequest is valid, false if invalid
	 */
	@Override
	public boolean validateToken(TokenValidationRequest tokenValidationRequest) {
		String token = tokenValidationRequest.getToken();
		JsonObject header = JwtUtil.decodeHeader(token);

		if (header == null || validateTokenHeader(header) == false) {
			return false;
		}

		JsonObject payload = JwtUtil.decodePayload(token);

		if (payload == null || validateGeneralInfo(payload) == false || validateTokenSignature(token) == false) {
			return false;
		}

		List<Boolean> toBeValidated = new ArrayList<>();

		if (tokenValidationRequest.getScopes() != null && !tokenValidationRequest.getScopes().isEmpty()) {
			toBeValidated.add(validateScopes(tokenValidationRequest, payload));
		}

		if (tokenValidationRequest.getRoles() != null && !tokenValidationRequest.getRoles().isEmpty()) {
			toBeValidated.add(validateRoles(tokenValidationRequest, payload));
		}

		if (tokenValidationRequest.getGroups() != null && !tokenValidationRequest.getGroups().isEmpty()) {
			toBeValidated.add(validateGroups(tokenValidationRequest, payload));
		}

		if (toBeValidated.isEmpty() == true) {
			return true;
		}

		if (tokenValidationRequest.isStrictValidation() == true) {
			return !toBeValidated.contains(false);
		}

		return toBeValidated.contains(true);

	}

	/**
	 * validate header part of access token.
	 *
	 * @param header to be validated.
	 * 
	 * @return true if header‚ is valid, false if invalid
	 */
	boolean validateTokenHeader(JsonObject header) {
		JsonObject jwks = cacheService.getJwks();

		if (jwks == null) {
			LOG.error("jwk is null!");
			throw new TokenValidationException("JWK invalid!");
		}

		JsonArray keys = jwks.getJsonArray("keys");

		if (keys == null || keys.isEmpty()) {
			LOG.error("keys couldn't be found!");
			throw new TokenValidationException("JWK invalid!");
		}

		String kid = header.getString("kid", null);
		String alg = header.getString("alg", null);

		if (kid == null || alg == null) {
			LOG.error("header is invalid!");
			throw new TokenValidationException("Header invalid!");
		}

		for (int i = 0; i < keys.size(); i++) {
			JsonObject key = keys.getJsonObject(i);
			String keyKid = key.getString("kid");
			String keyAlg = key.getString("alg");
			if (kid.equals(keyKid) && alg.equals(keyAlg)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * validate payload part of access token.
	 *
	 * @param payload to be validated.
	 * 
	 * @return true if payload is valid, false if invalid
	 */
	boolean validateGeneralInfo(JsonObject payload) {
		String baseUrl = ConfigProvider.getConfig()
				.getValue("de.cidaas.quarkus.extension.runtime.CidaasClient/mp-rest/url", String.class);

		if (payload.getString("iss", null) == null) {
			LOG.warn("token doesn't have iss!");
			return false;
		}

		if (!payload.getString("iss").equals(baseUrl)) {
			LOG.warn("iss is invalid!");
			return false;
		}

		int dateAsNumber = payload.getInt("exp");
		Instant expirationDate = Instant.ofEpochSecond(dateAsNumber);

		if (expirationDate.compareTo(Instant.now()) < 0) {
			LOG.warn("token is expired!");
			return false;
		}

		return true;
	}

	/**
	 * validate access token signature.
	 *
	 * @param token which signature will be validated.
	 * 
	 * @return true if signature is valid, false if invalid
	 */
	boolean validateTokenSignature(String token) {
		JsonObject jwks = cacheService.getJwks();
		SignedJWT signedJWT = null;
		try {
			signedJWT = SignedJWT.parse(token);
		} catch (ParseException e) {
			LOG.error("Failed to parse token", e);
			throw new TokenValidationException("Token cannot be parsed!");
		}
		JWKSet jwkSet = null;
		try {
			jwkSet = JWKSet.parse(jwks.toString());
		} catch (ParseException e) {
			LOG.error("Failed to parse jwks", e);
			throw new TokenValidationException("Jwks cannot be parsed!");
		}
		JWK jwk = jwkSet.getKeyByKeyId(signedJWT.getHeader().getKeyID());
		if (jwk == null) {
			LOG.error("No matching JWK found for kid: ", signedJWT.getHeader().getKeyID());
			throw new TokenValidationException("No matching Jwk found based on token kid" + signedJWT.getHeader().getKeyID());
		}
		JWSVerifier verifier = null;
		try {
			switch (jwk.getAlgorithm().getName()) {
				case "RS256": case "RS384": case "RS512": case "PS256": case "PS384": case "PS512":
					verifier = new RSASSAVerifier(jwk.toRSAKey());
					break;
				case "ES256": case "ES384": case "ES512":
					verifier = new ECDSAVerifier(jwk.toECKey());
					break;
				case "EdDSA":
					verifier = new Ed25519Verifier(jwk.toOctetKeyPair());
					break;
				default:
					throw new IllegalArgumentException("Unsupported alg: " + jwk.getAlgorithm().getName());
			}
		} catch (JOSEException e) {
			LOG.error("Error during initializing JWSVerifier", e.getMessage());
			throw new TokenValidationException("Error during initializing JWSVerifier" + e.getMessage());
		}
		boolean verified = false;
		try {
			verified = signedJWT.verify(verifier);
		} catch (JOSEException e) {
			LOG.error("Error during signature verification", e.getMessage());
			throw new TokenValidationException("Error during signature verification" + e.getMessage());
		}
		return verified;
	}

	private boolean validateScopes(TokenValidationRequest tokenValidationRequest, JsonObject payload) {
		JsonArray scopes = payload.getJsonArray("scopes");
		if (scopes == null) {
			return false;
		}
		List<String> scopesFromToken = scopes.getValuesAs(JsonString::getString);
		if (tokenValidationRequest.isStrictScopeValidation() == true
				&& !scopesFromToken.containsAll(tokenValidationRequest.getScopes())) {
			LOG.warn("token doesn't have enough scopes!");
			return false;
		}
		if (tokenValidationRequest.isStrictScopeValidation() == false && !scopesFromToken.stream()
				.anyMatch(element -> tokenValidationRequest.getScopes().contains(element))) {
			LOG.warn("token doesn't have enough scopes!");
			return false;
		}
		return true;
	}

	private boolean validateRoles(TokenValidationRequest tokenValidationRequest, JsonObject payload) {
		JsonArray roles = payload.getJsonArray("roles");
		if (roles == null) {
			return false;
		}
		List<String> rolesFromToken = roles.getValuesAs(JsonString::getString);
		if (tokenValidationRequest.isStrictRoleValidation() == true
				&& !rolesFromToken.containsAll(tokenValidationRequest.getRoles())) {
			LOG.warn("token doesn't have enough roles!");
			return false;
		}
		if (tokenValidationRequest.isStrictRoleValidation() == false
				&& !rolesFromToken.stream().anyMatch(element -> tokenValidationRequest.getRoles().contains(element))) {
			LOG.warn("token doesn't have enough roles!");
			return false;
		}
		return true;
	}

	private boolean validateGroups(TokenValidationRequest tokenValidationRequest, JsonObject payload) {
		JsonArray groups = payload.getJsonArray("groups");
		if (groups == null) {
			return false;
		}
		boolean strictGroupValidation = tokenValidationRequest.isStrictGroupValidation();
		boolean isAllGroupValid = true;

		List<Group> groupsFromToken = new ArrayList<>();
		for (int i = 0; i < groups.size(); i++) {
			JsonObject groupFromToken = groups.getJsonObject(i);
			String groupIdFromToken = groupFromToken.getString("groupId");
			List<String> groupRolesFromToken = groupFromToken.getJsonArray("roles").getValuesAs(JsonString::getString);
			Group group = new Group(groupIdFromToken, groupRolesFromToken);
			groupsFromToken.add(group);
		}

		for (Group groupFromValidationRequest : tokenValidationRequest.getGroups()) {
			boolean isGroupValid = validateGroup(groupFromValidationRequest, groupsFromToken);

			if (isGroupValid == true && strictGroupValidation == false) {
				return true;
			}
			if (isGroupValid == false) {
				isAllGroupValid = false;
				if (strictGroupValidation == true) {
					LOG.warn("token doesn't have enough groups!");
					return false;
				}
			}
		}

		return isAllGroupValid;

	}

	private boolean validateGroup(Group groupFromValidationRequest, List<Group> groupsFromToken) {
		String groupIdFromValidationRequest = groupFromValidationRequest.getGroupId();
		List<String> groupRolesFromValidationRequest = groupFromValidationRequest.getRoles();
		boolean strictGroupRoleValidation = groupFromValidationRequest.isStrictRoleValidation();

		for (Group groupFromToken : groupsFromToken) {
			if (groupFromToken.getGroupId().equals(groupIdFromValidationRequest)) {
				if (strictGroupRoleValidation == true
						&& groupFromToken.getRoles().containsAll(groupRolesFromValidationRequest)) {
					return true;
				}
				if (strictGroupRoleValidation == false && groupFromToken.getRoles().stream()
						.anyMatch(element -> groupRolesFromValidationRequest.contains(element))) {
					return true;
				}
			}
		}
		LOG.warn("grouproles is invalid!");
		return false;
	}

}
