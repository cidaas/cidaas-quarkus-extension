package de.cidaas.quarkus.extension.token.validation;

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

import de.cidaas.quarkus.extension.runtime.CacheService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.json.JsonObject;

@ApplicationScoped
public class NimbusJwtSignatureVerifier implements JwtSignatureVerifier {
    @Inject
	CacheService cacheService;

    private static final Logger LOG = LoggerFactory.getLogger(NimbusJwtSignatureVerifier.class);

    /**
	 * validate access token signature.
	 *
	 * @param token which signature will be validated.
	 * 
	 * @return true if signature is valid, false if invalid
	 */
    @Override
    public boolean validateTokenSignature(String token) {
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
}
