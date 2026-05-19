package de.cidaas.quarkus.extension.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import de.cidaas.quarkus.extension.token.validation.Group;
import de.cidaas.quarkus.extension.token.validation.IntrospectResponse;
import de.cidaas.quarkus.extension.token.validation.TokenValidationException;
import de.cidaas.quarkus.extension.token.validation.TokenValidationRequest;
import jakarta.json.JsonObject;

@ExtendWith(MockitoExtension.class)
class CidaasHttpClientIntrospectTest {

	@Mock
	CidaasExtensionConfig config;

	MockCidaasServer mockServer;
	CidaasHttpClient httpClient;
	CidaasInstanceService instanceService;

	@BeforeEach
	void setUp() throws Exception {
		mockServer = MockCidaasServer.start();
		when(config.clientId()).thenReturn("app-client-id");
		when(config.clientSecret()).thenReturn("app-client-secret");

		instanceService = new CidaasInstanceService();
		httpClient = new CidaasHttpClient();
		inject(httpClient, "instanceService", instanceService);
		inject(httpClient, "config", config);
	}

	@AfterEach
	void tearDown() {
		mockServer.close();
	}

	@Test
	void introspectPostsClientCredentialsAndRestrictions() {
		TokenValidationRequest request = new TokenValidationRequest();
		request.setToken("opaque-token");
		request.setScopes(List.of("profile", "email"));
		request.setRoles(List.of("ADMIN"));
		request.setStrictScopeValidation(true);
		request.setGroups(List.of(new Group("g1", "USER", List.of("r1", "r2"), true, true)));

		CidaasRequestMetadata metadata = CidaasRequestMetadata.minimal("opaque-token", mockServer.baseUrl + "/api");
		IntrospectResponse response = httpClient.introspect(mockServer.baseUrl, request, metadata);

		assertTrue(response.isActive());
		assertEquals("user-1", response.getSub());

		JsonObject body = MockCidaasServer.parseBody(mockServer.lastIntrospectBody.get());
		assertEquals("opaque-token", body.getString("token"));
		assertEquals("app-client-id", body.getString("client_id"));
		assertEquals("app-client-secret", body.getString("client_secret"));
		assertEquals("profile", body.getJsonArray("scopes").getString(0));
		assertEquals("ADMIN", body.getJsonArray("roles").getString(0));
		assertTrue(body.getBoolean("strictScopeValidation"));
		JsonObject sentGroup = body.getJsonArray("groups").getJsonObject(0);
		assertEquals("g1", sentGroup.getString("groupId"));
		assertEquals("USER", sentGroup.getString("groupType"));
		assertTrue(sentGroup.getBoolean("strictValidation"));
	}

	@Test
	void introspectDoesNotForwardInternalGatewayHeaders() throws Exception {
		mockServer.introspectHandler = (body, exchange) -> {
			assertFalse(exchange.getRequestHeaders().containsKey("x-ref-number"));
			assertFalse(exchange.getRequestHeaders().containsKey("x-client-ip"));
			assertFalse(exchange.getRequestHeaders().containsKey("wi-client-ip"));
			assertFalse(exchange.getRequestHeaders().containsKey("x-public-url"));
			MockCidaasServer.activeResponse(exchange, mockServer.baseUrl, "user-1");
		};

		TokenValidationRequest request = new TokenValidationRequest();
		request.setToken("t");
		httpClient.introspect(mockServer.baseUrl, request,
				CidaasRequestMetadata.minimal("t", mockServer.baseUrl + "/x"));
		assertNotNull(mockServer.lastIntrospectBody.get());
	}

	@Test
	void introspectThrowsOnNon200Response() {
		mockServer.introspectHandler = (body, exchange) -> MockCidaasServer.errorResponse(exchange, 401);

		TokenValidationRequest request = new TokenValidationRequest();
		request.setToken("t");
		assertThrows(TokenValidationException.class,
				() -> httpClient.introspect(mockServer.baseUrl, request,
						CidaasRequestMetadata.minimal("t", mockServer.baseUrl + "/x")));
	}

	@Test
	void introspectUsesCustomEndpointOverride() {
		String patEndpoint = mockServer.baseUrl + "/accesspass-srv/passes/pat/introspect";
		TokenValidationRequest request = new TokenValidationRequest();
		request.setToken("pat");
		request.setToken_type_hint("pat");

		httpClient.introspect(mockServer.baseUrl, request,
				CidaasRequestMetadata.minimal("pat", mockServer.baseUrl + "/x"), patEndpoint);

		assertNotNull(mockServer.lastIntrospectBody.get());
	}

	private static void inject(Object target, String fieldName, Object value) throws Exception {
		Field field = target.getClass().getDeclaredField(fieldName);
		field.setAccessible(true);
		field.set(target, value);
	}
}
