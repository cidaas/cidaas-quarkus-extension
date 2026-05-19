package de.cidaas.quarkus.extension.runtime;

import jakarta.json.JsonObject;

public class CidaasInstanceDetails {
	private final String issuer;
	private final String introspectionEndpoint;
	private final String jwksUri;
	private final JsonObject jwks;

	public CidaasInstanceDetails(String issuer, String introspectionEndpoint, String jwksUri, JsonObject jwks) {
		this.issuer = issuer;
		this.introspectionEndpoint = introspectionEndpoint;
		this.jwksUri = jwksUri;
		this.jwks = jwks;
	}

	public String getIssuer() {
		return issuer;
	}

	public String getIntrospectionEndpoint() {
		return introspectionEndpoint;
	}

	public String getJwksUri() {
		return jwksUri;
	}

	public JsonObject getJwks() {
		return jwks;
	}
}
