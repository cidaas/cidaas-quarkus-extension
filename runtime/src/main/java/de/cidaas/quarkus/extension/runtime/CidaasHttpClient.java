package de.cidaas.quarkus.extension.runtime;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.cidaas.quarkus.extension.token.validation.Group;
import de.cidaas.quarkus.extension.token.validation.IntrospectResponse;
import de.cidaas.quarkus.extension.token.validation.TokenValidationException;
import de.cidaas.quarkus.extension.token.validation.TokenValidationRequest;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.json.Json;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.json.JsonReader;

@ApplicationScoped
public class CidaasHttpClient {

	private static final Logger LOG = LoggerFactory.getLogger(CidaasHttpClient.class);
	private final HttpClient httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

	@Inject
	CidaasInstanceService instanceService;

	@Inject
	CidaasExtensionConfig config;

	public IntrospectResponse introspect(String baseUrl, TokenValidationRequest body, CidaasRequestMetadata metadata,
			String introspectionEndpointOverride) {
		try {
			CidaasInstanceDetails instance = instanceService.getInstanceDetails(baseUrl);
			String endpoint = introspectionEndpointOverride != null && !introspectionEndpointOverride.isBlank()
					? introspectionEndpointOverride
					: instance.getIntrospectionEndpoint();
			String payload = toJson(body);
			HttpRequest request = HttpRequest.newBuilder()
					.uri(URI.create(endpoint))
					.timeout(Duration.ofSeconds(10))
					.header("Content-Type", "application/json")
					.POST(HttpRequest.BodyPublishers.ofString(payload))
					.build();
			HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
			if (response.statusCode() != 200) {
				LOG.warn("Introspect returned status {}", response.statusCode());
				throw new TokenValidationException("Introspect call failed");
			}
			JsonObject json;
			try (JsonReader reader = Json.createReader(new java.io.StringReader(response.body()))) {
				json = reader.readObject();
			}
			return IntrospectResponse.fromJson(json);
		} catch (TokenValidationException e) {
			throw e;
		} catch (Exception e) {
			LOG.error("Introspect error", e);
			throw new TokenValidationException("Introspect call failed: " + e.getMessage());
		}
	}

	public IntrospectResponse introspect(String baseUrl, TokenValidationRequest body, CidaasRequestMetadata metadata) {
		return introspect(baseUrl, body, metadata, null);
	}

	private String toJson(TokenValidationRequest request) {
		JsonObjectBuilder builder = Json.createObjectBuilder().add("token", request.getToken());
		if (!config.clientId().isBlank()) {
			builder.add("client_id", config.clientId());
		}
		if (!config.clientSecret().isBlank()) {
			builder.add("client_secret", config.clientSecret());
		}
		if (request.getToken_type_hint() != null && !request.getToken_type_hint().isBlank()) {
			builder.add("token_type_hint", request.getToken_type_hint());
		}
		addStringArray(builder, "roles", request.getRoles());
		addStringArray(builder, "scopes", request.getScopes());
		if (request.getGroups() != null && !request.getGroups().isEmpty()) {
			JsonArrayBuilder groups = Json.createArrayBuilder();
			for (Group group : request.getGroups()) {
				JsonObjectBuilder g = Json.createObjectBuilder().add("groupId", group.getGroupId());
				if (group.getGroupType() != null && !group.getGroupType().isBlank()) {
					g.add("groupType", group.getGroupType());
				}
				if (group.getRoles() != null) {
					JsonArrayBuilder roles = Json.createArrayBuilder();
					group.getRoles().forEach(roles::add);
					g.add("roles", roles);
				}
				g.add("strictRoleValidation", group.isStrictRoleValidation());
				g.add("strictValidation", group.isStrictValidation());
				groups.add(g);
			}
			builder.add("groups", groups);
		}
		builder.add("strictGroupValidation", request.isStrictGroupValidation());
		builder.add("strictScopeValidation", request.isStrictScopeValidation());
		builder.add("strictRoleValidation", request.isStrictRoleValidation());
		builder.add("strictValidation", request.isStrictValidation());
		return builder.build().toString();
	}

	private void addStringArray(JsonObjectBuilder builder, String key, java.util.List<String> values) {
		if (values != null && !values.isEmpty()) {
			JsonArrayBuilder array = Json.createArrayBuilder();
			values.forEach(array::add);
			builder.add(key, array);
		}
	}
}
