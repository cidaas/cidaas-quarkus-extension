package de.cidaas.quarkus.extension.runtime;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.eclipse.microprofile.config.ConfigProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.cidaas.quarkus.extension.token.validation.TokenValidationException;
import io.quarkus.cache.CacheInvalidate;
import io.quarkus.cache.CacheResult;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;

@ApplicationScoped
public class CidaasInstanceService {

	private static final Logger LOG = LoggerFactory.getLogger(CidaasInstanceService.class);
	private final HttpClient httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
	private final Map<String, CidaasInstanceDetails> localCache = new ConcurrentHashMap<>();

	public CidaasInstanceDetails getInstanceDetails(String baseUrl) {
		return getInstanceDetails(baseUrl, false);
	}

	public CidaasInstanceDetails getInstanceDetails(String baseUrl, boolean refresh) {
		String normalized = normalizeBaseUrl(baseUrl);
		if (!refresh && localCache.containsKey(normalized)) {
			return localCache.get(normalized);
		}
		CidaasInstanceDetails details = loadInstanceDetails(normalized);
		localCache.put(normalized, details);
		return details;
	}

	@CacheResult(cacheName = "cidaas-jwk-cache")
	public JsonObject getJwks(String baseUrl) {
		return getInstanceDetails(baseUrl).getJwks();
	}

	@CacheInvalidate(cacheName = "cidaas-jwk-cache")
	public void invalidateJwksCache() {
		localCache.clear();
	}

	private CidaasInstanceDetails loadInstanceDetails(String baseUrl) {
		try {
			HttpRequest request = HttpRequest.newBuilder()
					.uri(URI.create(baseUrl + "/.well-known/openid-configuration"))
					.timeout(Duration.ofSeconds(10))
					.GET()
					.build();
			HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
			if (response.statusCode() != 200) {
				throw new TokenValidationException("openid-configuration returned " + response.statusCode());
			}
			JsonObject openId;
			try (JsonReader reader = Json.createReader(new java.io.StringReader(response.body()))) {
				openId = reader.readObject();
			}
			String issuer = openId.getString("issuer", baseUrl);
			String introspectionEndpoint = openId.getString("introspection_endpoint", baseUrl + "/token-srv/introspect");
			String jwksUri = openId.getString("jwks_uri", baseUrl + "/.well-known/jwks.json");
			JsonObject jwks = fetchJson(jwksUri);
			return new CidaasInstanceDetails(issuer, introspectionEndpoint, jwksUri, jwks);
		} catch (TokenValidationException e) {
			throw e;
		} catch (Exception e) {
			LOG.error("Failed to load instance details for {}", baseUrl, e);
			throw new TokenValidationException("Failed to load cidaas instance details: " + e.getMessage());
		}
	}

	private JsonObject fetchJson(String url) throws Exception {
		HttpRequest request = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(10)).GET()
				.build();
		HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
		if (response.statusCode() != 200) {
			throw new TokenValidationException("HTTP " + response.statusCode() + " for " + url);
		}
		try (JsonReader reader = Json.createReader(new java.io.StringReader(response.body()))) {
			return reader.readObject();
		}
	}

	public String defaultBaseUrl() {
		return ConfigProvider.getConfig()
				.getOptionalValue("de.cidaas.quarkus.extension.runtime.CidaasClient/mp-rest/url", String.class)
				.orElse("");
	}

	private String normalizeBaseUrl(String baseUrl) {
		if (baseUrl == null || baseUrl.isBlank()) {
			baseUrl = defaultBaseUrl();
		}
		if (baseUrl == null || baseUrl.isBlank()) {
			throw new TokenValidationException("Cidaas base URL is not configured");
		}
		if (!baseUrl.contains("://")) {
			baseUrl = "https://" + baseUrl;
		}
		if (baseUrl.endsWith("/")) {
			return baseUrl.substring(0, baseUrl.length() - 1);
		}
		return baseUrl;
	}
}
