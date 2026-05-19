package de.cidaas.quarkus.extension.runtime;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import de.cidaas.quarkus.extension.token.validation.ValidationMode;
import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class DPoPValidator {

	private static final Logger LOG = LoggerFactory.getLogger(DPoPValidator.class);

	public boolean validate(CidaasRequestMetadata metadata, String accessToken, String expectedJkt,
			ValidationMode mode) {
		if (mode == ValidationMode.OFF || expectedJkt == null || expectedJkt.isBlank()) {
			return true;
		}
		try {
			validateStrict(metadata, accessToken, expectedJkt);
			return true;
		} catch (Exception e) {
			LOG.warn("DPoP validation failed: {}", e.getMessage());
			return mode != ValidationMode.STRICT;
		}
	}

	private void validateStrict(CidaasRequestMetadata metadata, String accessToken, String expectedJkt)
			throws Exception {
		String dpopToken = metadata.getDpopHeader();
		if (dpopToken == null || dpopToken.isBlank()) {
			throw new IllegalStateException("no DPoP header provided");
		}
		SignedJWT jwt = SignedJWT.parse(dpopToken);
		if (!"dpop+jwt".equals(jwt.getHeader().getType().getType())) {
			throw new IllegalStateException("DPoP token does not have typ dpop+jwt");
		}
		JWK jwk = jwt.getHeader().getJWK();
		if (jwk == null) {
			throw new IllegalStateException("DPoP token does not contain JWK");
		}
		JWSVerifier verifier = createVerifier(jwk);
		if (!jwt.verify(verifier)) {
			throw new IllegalStateException("DPoP signature verification failed");
		}
		JWTClaimsSet claims = jwt.getJWTClaimsSet();
		if (!metadata.getHttpMethod().equals(claims.getStringClaim("htm"))) {
			throw new IllegalStateException("DPoP htm mismatch");
		}
		if (!metadata.getHttpUri().equals(claims.getStringClaim("htu"))) {
			throw new IllegalStateException("DPoP htu mismatch");
		}
		if (accessToken != null && !accessToken.isBlank()) {
			String ath = claims.getStringClaim("ath");
			String expectedAth = base64UrlSha256(accessToken);
			if (!expectedAth.equals(ath)) {
				throw new IllegalStateException("DPoP ath mismatch");
			}
		}
		String thumbprint = jwk.computeThumbprint("SHA-256").toString();
		if (!expectedJkt.equals(thumbprint)) {
			throw new IllegalStateException("JWK thumbprint mismatch");
		}
	}

	private static JWSVerifier createVerifier(JWK jwk) throws Exception {
		return switch (jwk.getAlgorithm().getName()) {
		case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512" -> new RSASSAVerifier(jwk.toRSAKey());
		case "ES256", "ES384", "ES512" -> new ECDSAVerifier(jwk.toECKey());
		case "EdDSA" -> new Ed25519Verifier(jwk.toOctetKeyPair());
		default -> throw new IllegalArgumentException("Unsupported alg: " + jwk.getAlgorithm().getName());
		};
	}

	private static String base64UrlSha256(String value) throws Exception {
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
		return Base64URL.encode(hash).toString();
	}
}
