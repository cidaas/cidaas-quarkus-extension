package de.cidaas.quarkus.extension.runtime;

import java.text.ParseException;

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

import de.cidaas.quarkus.extension.token.validation.TokenValidationException;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.json.JsonObject;

@ApplicationScoped
public class NimbusJwtSignatureVerifier {

	@Inject
	CidaasInstanceService instanceService;

	private static final Logger LOG = LoggerFactory.getLogger(NimbusJwtSignatureVerifier.class);

	public boolean validateTokenSignature(String token, String baseUrl) {
		JsonObject jwks = instanceService.getJwks(baseUrl);
		SignedJWT signedJWT;
		try {
			signedJWT = SignedJWT.parse(token);
		} catch (ParseException e) {
			LOG.error("Failed to parse token", e);
			throw new TokenValidationException("Token cannot be parsed!");
		}
		JWKSet jwkSet;
		try {
			jwkSet = JWKSet.parse(jwks.toString());
		} catch (ParseException e) {
			throw new TokenValidationException("Jwks cannot be parsed!");
		}
		JWK jwk = jwkSet.getKeyByKeyId(signedJWT.getHeader().getKeyID());
		if (jwk == null) {
			instanceService.getInstanceDetails(baseUrl, true);
			jwks = instanceService.getJwks(baseUrl);
			try {
				jwkSet = JWKSet.parse(jwks.toString());
			} catch (ParseException e) {
				throw new TokenValidationException("Jwks cannot be parsed!");
			}
			jwk = jwkSet.getKeyByKeyId(signedJWT.getHeader().getKeyID());
			if (jwk == null) {
				return false;
			}
		}
		try {
			JWSVerifier verifier = switch (jwk.getAlgorithm().getName()) {
			case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512" -> new RSASSAVerifier(jwk.toRSAKey());
			case "ES256", "ES384", "ES512" -> new ECDSAVerifier(jwk.toECKey());
			case "EdDSA" -> new Ed25519Verifier(jwk.toOctetKeyPair());
			default -> throw new IllegalArgumentException("Unsupported alg: " + jwk.getAlgorithm().getName());
			};
			return signedJWT.verify(verifier);
		} catch (JOSEException e) {
			LOG.error("Signature verification failed", e);
			return false;
		}
	}
}
