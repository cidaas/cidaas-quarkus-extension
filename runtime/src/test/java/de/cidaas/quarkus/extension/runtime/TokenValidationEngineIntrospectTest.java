package de.cidaas.quarkus.extension.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import de.cidaas.quarkus.extension.token.validation.Group;
import de.cidaas.quarkus.extension.token.validation.TokenValidationRequest;
import de.cidaas.quarkus.extension.token.validation.ValidationMode;
import de.cidaas.quarkus.extension.token.validation.ValidationResult;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TokenValidationEngineIntrospectTest {

	@Mock
	CidaasExtensionConfig config;

	@Mock
	OfflineTokenValidationService offlineTokenValidationService;

	MockCidaasServer mockServer;
	TokenValidationEngine engine;
	CidaasHttpClient httpClient;
	CidaasInstanceService instanceService;
	DPoPValidator dpopValidator;

	@BeforeEach
	void setUp() throws Exception {
		mockServer = MockCidaasServer.start();
		when(config.clientId()).thenReturn("app-client-id");
		when(config.clientSecret()).thenReturn("app-client-secret");
		instanceService = new CidaasInstanceService();
		httpClient = new CidaasHttpClient();
		inject(httpClient, "instanceService", instanceService);
		inject(httpClient, "config", config);

		dpopValidator = new DPoPValidator();
		engine = new TokenValidationEngine();
		inject(engine, "httpClient", httpClient);
		inject(engine, "instanceService", instanceService);
		inject(engine, "offlineTokenValidationService", offlineTokenValidationService);
		inject(engine, "dpopValidator", dpopValidator);
		inject(engine, "config", config);
	}

	@AfterEach
	void tearDown() {
		mockServer.close();
	}

	@Test
	void introspectSuccessReturnsTokenData() {
		TokenValidationRequest request = new TokenValidationRequest();
		request.setToken("opaque");
		CidaasRequestMetadata metadata = CidaasRequestMetadata.minimal("opaque", mockServer.baseUrl + "/api");

		ValidationResult result = engine.validate(request, metadata, mockServer.baseUrl, false,
				ValidationMode.OFF, ValidationMode.OFF, ValidationMode.OFF);

		assertTrue(result.isValid());
		assertEquals("user-1", result.getTokenData().getSub());
		assertTrue(result.getTokenData().getScopes().contains("profile"));
	}

	@Test
	void introspectInactiveTokenRejected() {
		mockServer.introspectHandler = (body, exchange) -> MockCidaasServer.inactiveResponse(exchange);

		TokenValidationRequest request = new TokenValidationRequest();
		request.setToken("opaque");
		request.setScopes(List.of("profile"));
		CidaasRequestMetadata metadata = CidaasRequestMetadata.minimal("opaque", mockServer.baseUrl + "/api");

		ValidationResult result = engine.validate(request, metadata, mockServer.baseUrl, false,
				ValidationMode.OFF, ValidationMode.OFF, ValidationMode.OFF);

		assertFalse(result.isValid());
	}

	@Test
	void introspectWrongIssuerRejected() {
		mockServer.introspectHandler = (body, exchange) -> MockCidaasServer.activeResponse(exchange,
				"https://wrong-issuer.example", "user-1");

		TokenValidationRequest request = new TokenValidationRequest();
		request.setToken("opaque");
		ValidationResult result = engine.validate(request,
				CidaasRequestMetadata.minimal("opaque", mockServer.baseUrl + "/api"),
				mockServer.baseUrl, false, ValidationMode.OFF, ValidationMode.OFF, ValidationMode.OFF);

		assertFalse(result.isValid());
	}

	@Test
	void introspectSendsScopeRoleGroupRestrictionsToCidaas() {
		TokenValidationRequest request = new TokenValidationRequest();
		request.setToken("opaque");
		request.setScopes(List.of("profile"));
		request.setRoles(List.of("ADMIN"));
		request.setGroups(List.of(new Group("g1", "USER", List.of("r1"), false, false)));
		request.setStrictScopeValidation(true);

		engine.validate(request, CidaasRequestMetadata.minimal("opaque", mockServer.baseUrl + "/api"),
				mockServer.baseUrl, false, ValidationMode.OFF, ValidationMode.OFF, ValidationMode.OFF);

		String body = mockServer.lastIntrospectBody.get();
		assertTrue(body.contains("\"scopes\""));
		assertTrue(body.contains("\"roles\""));
		assertTrue(body.contains("\"groupType\":\"USER\""));
		assertTrue(body.contains("\"strictScopeValidation\":true"));
	}

	@Test
	void offlineValidationDelegatesToOfflineService() {
		TokenValidationRequest request = new TokenValidationRequest();
		request.setToken("jwt");
		when(offlineTokenValidationService.validateToken(request, mockServer.baseUrl, ValidationMode.OFF))
				.thenReturn(false);

		ValidationResult result = engine.validate(request,
				CidaasRequestMetadata.minimal("jwt", mockServer.baseUrl + "/api"),
				mockServer.baseUrl, true, ValidationMode.OFF, ValidationMode.OFF, ValidationMode.OFF);

		assertFalse(result.isValid());
		verify(offlineTokenValidationService).validateToken(request, mockServer.baseUrl, ValidationMode.OFF);
	}

	@Test
	void missingBaseUrlReturnsInvalid() {
		when(config.baseUrl()).thenReturn("");
		TokenValidationRequest request = new TokenValidationRequest();
		request.setToken("opaque");

		ValidationResult result = engine.validate(request, CidaasRequestMetadata.minimal("opaque", ""),
				"", false, ValidationMode.OFF, ValidationMode.OFF, ValidationMode.OFF);

		assertFalse(result.isValid());
	}

	@Test
	void resolveBaseUrlFromExtensionConfig() {
		when(config.baseUrl()).thenReturn(mockServer.baseUrl);
		TokenValidationRequest request = new TokenValidationRequest();
		request.setToken("opaque");

		ValidationResult result = engine.validate(request,
				CidaasRequestMetadata.minimal("opaque", mockServer.baseUrl + "/api"),
				"", false, ValidationMode.OFF, ValidationMode.OFF, ValidationMode.OFF);

		assertTrue(result.isValid());
	}

	@Test
	void introspectIssuerCaseInsensitiveMatch() {
		mockServer.introspectHandler = (body, exchange) -> MockCidaasServer.activeResponse(exchange,
				mockServer.baseUrl.toUpperCase(), "user-upper");

		TokenValidationRequest request = new TokenValidationRequest();
		request.setToken("opaque");
		ValidationResult result = engine.validate(request,
				CidaasRequestMetadata.minimal("opaque", mockServer.baseUrl + "/api"),
				mockServer.baseUrl, false, ValidationMode.OFF, ValidationMode.OFF, ValidationMode.OFF);

		assertTrue(result.isValid());
		assertEquals("user-upper", result.getTokenData().getSub());
	}

	@Test
	void introspectHttpErrorReturnsInvalid() {
		mockServer.introspectHandler = (body, exchange) -> MockCidaasServer.errorResponse(exchange, 500);

		TokenValidationRequest request = new TokenValidationRequest();
		request.setToken("opaque");
		ValidationResult result = engine.validate(request,
				CidaasRequestMetadata.minimal("opaque", mockServer.baseUrl + "/api"),
				mockServer.baseUrl, false, ValidationMode.OFF, ValidationMode.OFF, ValidationMode.OFF);

		assertFalse(result.isValid());
	}

	@Test
	void introspectDpopReportModeAllowsMissingHeader() {
		mockServer.introspectHandler = (body, exchange) -> MockCidaasServer.activeResponseWithCnf(exchange,
				mockServer.baseUrl, "user-1", "expected-jkt", null);

		TokenValidationRequest request = new TokenValidationRequest();
		request.setToken("opaque");
		ValidationResult result = engine.validate(request,
				CidaasRequestMetadata.minimal("opaque", mockServer.baseUrl + "/api"),
				mockServer.baseUrl, false, ValidationMode.REPORT, ValidationMode.OFF, ValidationMode.OFF);

		assertTrue(result.isValid());
	}

	@Test
	void introspectMtlsReportModeAllowsMissingFingerprint() {
		mockServer.introspectHandler = (body, exchange) -> MockCidaasServer.activeResponseWithCnf(exchange,
				mockServer.baseUrl, "user-1", null, "dGVzdA==");

		TokenValidationRequest request = new TokenValidationRequest();
		request.setToken("opaque");
		ValidationResult result = engine.validate(request,
				CidaasRequestMetadata.minimal("opaque", mockServer.baseUrl + "/api"),
				mockServer.baseUrl, false, ValidationMode.OFF, ValidationMode.REPORT, ValidationMode.OFF);

		assertTrue(result.isValid());
	}

	@Test
	void introspectDpopStrictModeRejectsMissingHeader() {
		mockServer.introspectHandler = (body, exchange) -> MockCidaasServer.activeResponseWithCnf(exchange,
				mockServer.baseUrl, "user-1", "expected-jkt", null);

		TokenValidationRequest request = new TokenValidationRequest();
		request.setToken("opaque");
		ValidationResult result = engine.validate(request,
				CidaasRequestMetadata.minimal("opaque", mockServer.baseUrl + "/api"),
				mockServer.baseUrl, false, ValidationMode.STRICT, ValidationMode.OFF, ValidationMode.OFF);

		assertFalse(result.isValid());
	}

	@Test
	void introspectMtlsStrictModeRejectsFingerprintMismatch() {
		mockServer.introspectHandler = (body, exchange) -> MockCidaasServer.activeResponseWithCnf(exchange,
				mockServer.baseUrl, "user-1", null, "dGVzdA==");

		CidaasRequestMetadata metadata = CidaasRequestMetadata.withMtlsFingerprint("opaque",
				mockServer.baseUrl + "/api", "aa:bb:cc:dd");
		TokenValidationRequest request = new TokenValidationRequest();
		request.setToken("opaque");

		ValidationResult result = engine.validate(request, metadata, mockServer.baseUrl, false,
				ValidationMode.OFF, ValidationMode.STRICT, ValidationMode.OFF);

		assertFalse(result.isValid());
	}

	@Test
	void offlineValidationRejectsNullPayload() {
		when(offlineTokenValidationService.validateToken(
				org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.eq(mockServer.baseUrl),
				org.mockito.ArgumentMatchers.eq(ValidationMode.OFF))).thenReturn(true);

		TokenValidationRequest request = new TokenValidationRequest();
		request.setToken("not-a-jwt");
		ValidationResult result = engine.validate(request,
				CidaasRequestMetadata.minimal("not-a-jwt", mockServer.baseUrl + "/api"),
				mockServer.baseUrl, true, ValidationMode.OFF, ValidationMode.OFF, ValidationMode.OFF);

		assertFalse(result.isValid());
	}

	@Test
	void patMissingBaseUrlReturnsInvalid() {
		when(config.baseUrl()).thenReturn("");
		TokenValidationRequest request = new TokenValidationRequest();
		request.setToken("pat");

		ValidationResult result = engine.validatePat(request,
				CidaasRequestMetadata.minimal("pat", ""), "");

		assertFalse(result.isValid());
	}

	@Test
	void patIntrospectUsesPatEndpoint() {
		TokenValidationRequest request = new TokenValidationRequest();
		request.setToken("pat-token");
		request.setScopes(List.of("profile"));

		ValidationResult result = engine.validatePat(request,
				CidaasRequestMetadata.minimal("pat-token", mockServer.baseUrl + "/api"), mockServer.baseUrl);

		assertTrue(result.isValid());
		assertTrue(mockServer.lastIntrospectBody.get().contains("\"token_type_hint\":\"pat\""));
	}

	private static void inject(Object target, String fieldName, Object value) throws Exception {
		Field field = target.getClass().getDeclaredField(fieldName);
		field.setAccessible(true);
		field.set(target, value);
	}
}
