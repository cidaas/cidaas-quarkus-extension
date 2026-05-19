package de.cidaas.quarkus.extension.runtime;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.UriInfo;

/**
 * Request data required for public v4 validation (Bearer, DPoP, mTLS binding, HTTP target for DPoP).
 * Does not carry internal gateway metadata (x-public-url, x-ref-number, client-ip propagation).
 */
public class CidaasRequestMetadata {
	public static final String HEADER_MTLS_FINGERPRINT = "WI-Client-Cert-Fingerprint";

	private final String mtlsFingerprint;
	private final String accessToken;
	private final String dpopHeader;
	private final String httpMethod;
	private final String httpUri;

	private CidaasRequestMetadata(String mtlsFingerprint, String accessToken, String dpopHeader,
			String httpMethod, String httpUri) {
		this.mtlsFingerprint = mtlsFingerprint;
		this.accessToken = accessToken;
		this.dpopHeader = dpopHeader;
		this.httpMethod = httpMethod;
		this.httpUri = httpUri;
	}

	public static CidaasRequestMetadata minimal(String accessToken, String httpUri) {
		return new CidaasRequestMetadata(null, accessToken, null, "GET", httpUri);
	}

	public static CidaasRequestMetadata withMtlsFingerprint(String accessToken, String httpUri, String mtlsFingerprint) {
		return new CidaasRequestMetadata(mtlsFingerprint, accessToken, null, "GET", httpUri);
	}

	public static CidaasRequestMetadata from(ContainerRequestContext ctx) {
		String auth = ctx.getHeaderString("Authorization");
		String accessToken = "";
		if (auth != null) {
			String[] parts = auth.split(" ", 2);
			accessToken = parts.length > 1 ? parts[1] : parts[0];
		}
		String dpop = ctx.getHeaderString("DPoP");
		if (dpop == null || dpop.isBlank()) {
			dpop = ctx.getHeaderString("Dpop");
		}
		UriInfo uriInfo = ctx.getUriInfo();
		String scheme = uriInfo.getRequestUri().getScheme();
		if ("https".equalsIgnoreCase(ctx.getHeaderString("X-Forwarded-Proto"))) {
			scheme = "https";
		}
		String httpUri = scheme + "://" + uriInfo.getRequestUri().getAuthority() + uriInfo.getRequestUri().getPath();
		return new CidaasRequestMetadata(
				ctx.getHeaderString(HEADER_MTLS_FINGERPRINT),
				accessToken,
				dpop,
				ctx.getMethod(),
				httpUri);
	}

	public String getMtlsFingerprint() {
		return mtlsFingerprint;
	}

	public String getAccessToken() {
		return accessToken;
	}

	public String getDpopHeader() {
		return dpopHeader;
	}

	public String getHttpMethod() {
		return httpMethod;
	}

	public String getHttpUri() {
		return httpUri;
	}
}
