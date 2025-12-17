package de.cidaas.quarkus.extension.token.validation;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Arrays;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import de.cidaas.quarkus.extension.runtime.CacheService;
import de.cidaas.quarkus.extension.runtime.CustomTestProfile;
import de.cidaas.quarkus.extension.token.validation.MockService.PayloadOptions;
import de.cidaas.quarkus.extension.token.validation.MockService.ValidationOptions;
import io.quarkus.test.InjectMock;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import jakarta.json.Json;
import jakarta.json.JsonObject;

@QuarkusTest
@TestProfile(CustomTestProfile.class)
public class OfflineTokenValidationServiceTest {

	@Inject
	OfflineTokenValidationService offlineTokenValidationService;

	@Inject
	MockService mockService;

	@InjectMock
	CacheService cacheService;

	@InjectMock
	JwtSignatureVerifier signatureVerifier;

	JsonObject header;
	TokenValidationRequest tokenValidationRequest;

	@BeforeEach
	public void initEach() {
		when(cacheService.getJwks()).thenReturn(mockService.createJwks());
		when(signatureVerifier.validateTokenSignature(null)).thenReturn(true);
		doNothing().when(cacheService).refreshJwks();
		header = mockService.createHeader();
		tokenValidationRequest = mockService.createValidationRequest();
	}

	@Test
	public void testValidateToken_noHeader() {
		try (MockedStatic<JwtUtil> mockStatic = Mockito.mockStatic(JwtUtil.class)) {
			mockStatic.when(() -> JwtUtil.decodeHeader(null)).thenReturn(null);
			assertFalse(offlineTokenValidationService.validateToken(tokenValidationRequest));
		}
	}

	@Test
	public void testValidateToken_noPayload() {
		try (MockedStatic<JwtUtil> mockStatic = Mockito.mockStatic(JwtUtil.class)) {
			mockStatic.when(() -> JwtUtil.decodeHeader(null)).thenReturn(header);
			mockStatic.when(() -> JwtUtil.decodePayload(null)).thenReturn(null);
			assertFalse(offlineTokenValidationService.validateToken(tokenValidationRequest));
		}
	}

	@Test
	public void testValidateToken_scopeFlexibleInvalid() {
		try (MockedStatic<JwtUtil> mockStatic = Mockito.mockStatic(JwtUtil.class)) {
			mockStatic.when(() -> JwtUtil.decodeHeader(null)).thenReturn(header);
			mockStatic.when(() -> JwtUtil.decodePayload(null)).thenReturn(
					mockService.createPayload(Arrays.asList(PayloadOptions.SCOPE, PayloadOptions.SCOPE_NOT_EXIST)));
			assertFalse(offlineTokenValidationService.validateToken(tokenValidationRequest));
		}
	}

	@Test
	public void testValidateToken_scopeFlexibleValid() {
		try (MockedStatic<JwtUtil> mockStatic = Mockito.mockStatic(JwtUtil.class)) {
			mockStatic.when(() -> JwtUtil.decodeHeader(null)).thenReturn(header);
			mockStatic.when(() -> JwtUtil.decodePayload(null)).thenReturn(
					mockService.createPayload(Arrays.asList(PayloadOptions.SCOPE, PayloadOptions.SCOPE_NOT_COMPLETE)));
			assertTrue(offlineTokenValidationService.validateToken(tokenValidationRequest));
		}
	}

	@Test
	public void testValidateToken_scopeStrictInvalid() {
		try (MockedStatic<JwtUtil> mockStatic = Mockito.mockStatic(JwtUtil.class)) {
			mockStatic.when(() -> JwtUtil.decodeHeader(null)).thenReturn(header);
			mockStatic.when(() -> JwtUtil.decodePayload(null)).thenReturn(
					mockService.createPayload(Arrays.asList(PayloadOptions.SCOPE, PayloadOptions.SCOPE_NOT_COMPLETE)));
			tokenValidationRequest = mockService
					.createValidationRequest(Arrays.asList(ValidationOptions.SCOPE, ValidationOptions.SCOPE_STRICT));
			assertFalse(offlineTokenValidationService.validateToken(tokenValidationRequest));
		}
	}

	@Test
	public void testValidateToken_scopeStrictValid() {
		try (MockedStatic<JwtUtil> mockStatic = Mockito.mockStatic(JwtUtil.class)) {
			mockStatic.when(() -> JwtUtil.decodeHeader(null)).thenReturn(header);
			mockStatic.when(() -> JwtUtil.decodePayload(null))
					.thenReturn(mockService.createPayload(Arrays.asList(PayloadOptions.SCOPE)));
			tokenValidationRequest = mockService
					.createValidationRequest(Arrays.asList(ValidationOptions.SCOPE, ValidationOptions.SCOPE_STRICT));
			assertTrue(offlineTokenValidationService.validateToken(tokenValidationRequest));
		}
	}

	@Test
	public void testValidateToken_roleFlexibleInvalid() {
		try (MockedStatic<JwtUtil> mockStatic = Mockito.mockStatic(JwtUtil.class)) {
			mockStatic.when(() -> JwtUtil.decodeHeader(null)).thenReturn(header);
			mockStatic.when(() -> JwtUtil.decodePayload(null)).thenReturn(
					mockService.createPayload(Arrays.asList(PayloadOptions.ROLE, PayloadOptions.ROLE_NOT_EXIST)));
			assertFalse(offlineTokenValidationService.validateToken(tokenValidationRequest));
		}
	}

	@Test
	public void testValidateToken_roleFlexibleValid() {
		try (MockedStatic<JwtUtil> mockStatic = Mockito.mockStatic(JwtUtil.class)) {
			mockStatic.when(() -> JwtUtil.decodeHeader(null)).thenReturn(header);
			mockStatic.when(() -> JwtUtil.decodePayload(null)).thenReturn(
					mockService.createPayload(Arrays.asList(PayloadOptions.ROLE, PayloadOptions.ROLE_NOT_COMPLETE)));
			assertTrue(offlineTokenValidationService.validateToken(tokenValidationRequest));
		}
	}

	@Test
	public void testValidateToken_roleStrictInvalid() {
		try (MockedStatic<JwtUtil> mockStatic = Mockito.mockStatic(JwtUtil.class)) {
			mockStatic.when(() -> JwtUtil.decodeHeader(null)).thenReturn(header);
			mockStatic.when(() -> JwtUtil.decodePayload(null)).thenReturn(
					mockService.createPayload(Arrays.asList(PayloadOptions.ROLE, PayloadOptions.ROLE_NOT_COMPLETE)));
			tokenValidationRequest = mockService
					.createValidationRequest(Arrays.asList(ValidationOptions.ROLE, ValidationOptions.ROLE_STRICT));
			assertFalse(offlineTokenValidationService.validateToken(tokenValidationRequest));
		}
	}

	@Test
	public void testValidateToken_roleStrictValid() {
		try (MockedStatic<JwtUtil> mockStatic = Mockito.mockStatic(JwtUtil.class)) {
			mockStatic.when(() -> JwtUtil.decodeHeader(null)).thenReturn(header);
			mockStatic.when(() -> JwtUtil.decodePayload(null))
					.thenReturn(mockService.createPayload(Arrays.asList(PayloadOptions.ROLE)));
			tokenValidationRequest = mockService
					.createValidationRequest(Arrays.asList(ValidationOptions.ROLE, ValidationOptions.ROLE_STRICT));
			assertTrue(offlineTokenValidationService.validateToken(tokenValidationRequest));
		}
	}

	@Test
	public void testValidateToken_groupFlexibleInvalid() {
		try (MockedStatic<JwtUtil> mockStatic = Mockito.mockStatic(JwtUtil.class)) {
			mockStatic.when(() -> JwtUtil.decodeHeader(null)).thenReturn(header);
			mockStatic.when(() -> JwtUtil.decodePayload(null)).thenReturn(
					mockService.createPayload(Arrays.asList(PayloadOptions.GROUP, PayloadOptions.GROUP_NOT_EXIST)));
			assertFalse(offlineTokenValidationService.validateToken(tokenValidationRequest));
		}
	}

	@Test
	public void testValidateToken_groupFlexibleValid() {
		try (MockedStatic<JwtUtil> mockStatic = Mockito.mockStatic(JwtUtil.class)) {
			mockStatic.when(() -> JwtUtil.decodeHeader(null)).thenReturn(header);
			mockStatic.when(() -> JwtUtil.decodePayload(null)).thenReturn(
					mockService.createPayload(Arrays.asList(PayloadOptions.GROUP, PayloadOptions.GROUP_NOT_COMPLETE)));
			assertTrue(offlineTokenValidationService.validateToken(tokenValidationRequest));
		}
	}

	@Test
	public void testValidateToken_groupStrictInvalid() {
		try (MockedStatic<JwtUtil> mockStatic = Mockito.mockStatic(JwtUtil.class)) {
			mockStatic.when(() -> JwtUtil.decodeHeader(null)).thenReturn(header);
			mockStatic.when(() -> JwtUtil.decodePayload(null)).thenReturn(
					mockService.createPayload(Arrays.asList(PayloadOptions.GROUP, PayloadOptions.GROUP_NOT_COMPLETE)));
			tokenValidationRequest = mockService
					.createValidationRequest(Arrays.asList(ValidationOptions.GROUP, ValidationOptions.GROUP_STRICT));
			assertFalse(offlineTokenValidationService.validateToken(tokenValidationRequest));
		}
	}

	@Test
	public void testValidateToken_groupStrictValid() {
		try (MockedStatic<JwtUtil> mockStatic = Mockito.mockStatic(JwtUtil.class)) {
			mockStatic.when(() -> JwtUtil.decodeHeader(null)).thenReturn(header);
			mockStatic.when(() -> JwtUtil.decodePayload(null))
					.thenReturn(mockService.createPayload(Arrays.asList(PayloadOptions.GROUP)));
			tokenValidationRequest = mockService
					.createValidationRequest(Arrays.asList(ValidationOptions.GROUP, ValidationOptions.GROUP_STRICT));
			assertTrue(offlineTokenValidationService.validateToken(tokenValidationRequest));
		}
	}

	@Test
	public void testValidateToken_grouproleFlexibleInvalid() {
		try (MockedStatic<JwtUtil> mockStatic = Mockito.mockStatic(JwtUtil.class)) {
			mockStatic.when(() -> JwtUtil.decodeHeader(null)).thenReturn(header);
			mockStatic.when(() -> JwtUtil.decodePayload(null)).thenReturn(mockService
					.createPayload(Arrays.asList(PayloadOptions.GROUPROLE, PayloadOptions.GROUPROLE_NOT_EXIST)));
			assertFalse(offlineTokenValidationService.validateToken(tokenValidationRequest));
		}
	}

	@Test
	public void testValidateToken_grouproleFlexibleValid() {
		try (MockedStatic<JwtUtil> mockStatic = Mockito.mockStatic(JwtUtil.class)) {
			mockStatic.when(() -> JwtUtil.decodeHeader(null)).thenReturn(header);
			mockStatic.when(() -> JwtUtil.decodePayload(null)).thenReturn(mockService
					.createPayload(Arrays.asList(PayloadOptions.GROUPROLE, PayloadOptions.GROUPROLE_NOT_COMPLETE)));
			assertTrue(offlineTokenValidationService.validateToken(tokenValidationRequest));
		}
	}

	@Test
	public void testValidateToken_grouproleStrictInvalid() {
		try (MockedStatic<JwtUtil> mockStatic = Mockito.mockStatic(JwtUtil.class)) {
			mockStatic.when(() -> JwtUtil.decodeHeader(null)).thenReturn(header);
			mockStatic.when(() -> JwtUtil.decodePayload(null)).thenReturn(mockService
					.createPayload(Arrays.asList(PayloadOptions.GROUPROLE, PayloadOptions.GROUPROLE_NOT_COMPLETE)));
			tokenValidationRequest = mockService.createValidationRequest(
					Arrays.asList(ValidationOptions.GROUP, ValidationOptions.GROUPROLE_STRICT));
			assertFalse(offlineTokenValidationService.validateToken(tokenValidationRequest));
		}
	}

	@Test
	public void testValidateToken_grouproleStrictValid() {
		try (MockedStatic<JwtUtil> mockStatic = Mockito.mockStatic(JwtUtil.class)) {
			mockStatic.when(() -> JwtUtil.decodeHeader(null)).thenReturn(header);
			mockStatic.when(() -> JwtUtil.decodePayload(null))
					.thenReturn(mockService.createPayload(Arrays.asList(PayloadOptions.GROUPROLE)));
			tokenValidationRequest = mockService.createValidationRequest(
					Arrays.asList(ValidationOptions.GROUP, ValidationOptions.GROUPROLE_STRICT));
			assertTrue(offlineTokenValidationService.validateToken(tokenValidationRequest));
		}
	}

	@Test
	public void testValidateToken_flexibleValidationInvalid() {
		try (MockedStatic<JwtUtil> mockStatic = Mockito.mockStatic(JwtUtil.class)) {
			mockStatic.when(() -> JwtUtil.decodeHeader(null)).thenReturn(header);
			mockStatic.when(() -> JwtUtil.decodePayload(null))
					.thenReturn(mockService.createPayload(Arrays.asList(PayloadOptions.ROLE,
							PayloadOptions.ROLE_NOT_EXIST, PayloadOptions.SCOPE, PayloadOptions.SCOPE_NOT_EXIST)));
			assertFalse(offlineTokenValidationService.validateToken(tokenValidationRequest));
		}
	}

	@Test
	public void testValidateToken_flexibleValidationValid() {
		try (MockedStatic<JwtUtil> mockStatic = Mockito.mockStatic(JwtUtil.class)) {
			mockStatic.when(() -> JwtUtil.decodeHeader(null)).thenReturn(header);
			mockStatic.when(() -> JwtUtil.decodePayload(null)).thenReturn(mockService.createPayload(
					Arrays.asList(PayloadOptions.ROLE, PayloadOptions.SCOPE, PayloadOptions.SCOPE_NOT_EXIST)));
			assertTrue(offlineTokenValidationService.validateToken(tokenValidationRequest));
		}
	}

	@Test
	public void testValidateToken_strictValidationInvalid() {
		try (MockedStatic<JwtUtil> mockStatic = Mockito.mockStatic(JwtUtil.class)) {
			mockStatic.when(() -> JwtUtil.decodeHeader(null)).thenReturn(header);
			mockStatic.when(() -> JwtUtil.decodePayload(null)).thenReturn(mockService.createPayload(
					Arrays.asList(PayloadOptions.ROLE, PayloadOptions.SCOPE, PayloadOptions.SCOPE_NOT_EXIST)));
			tokenValidationRequest = mockService.createValidationRequest(Arrays.asList(ValidationOptions.ROLE,
					ValidationOptions.SCOPE, ValidationOptions.VALIDATION_STRICT));
			assertFalse(offlineTokenValidationService.validateToken(tokenValidationRequest));
		}
	}

	@Test
	public void testValidateToken_strictValidationValid() {
		try (MockedStatic<JwtUtil> mockStatic = Mockito.mockStatic(JwtUtil.class)) {
			mockStatic.when(() -> JwtUtil.decodeHeader(null)).thenReturn(header);
			mockStatic.when(() -> JwtUtil.decodePayload(null))
					.thenReturn(mockService.createPayload(Arrays.asList(PayloadOptions.ROLE, PayloadOptions.SCOPE)));
			tokenValidationRequest = mockService.createValidationRequest(Arrays.asList(ValidationOptions.ROLE,
					ValidationOptions.SCOPE, ValidationOptions.VALIDATION_STRICT));
			assertTrue(offlineTokenValidationService.validateToken(tokenValidationRequest));
		}
	}

	@Test
	public void testValidateTokenHeader_emptyJwks() {
		JsonObject emptyJwks = Json.createObjectBuilder().add("keys", Json.createArrayBuilder()).build();
		when(cacheService.getJwks()).thenReturn(emptyJwks);
		TokenValidationException exception = assertThrows(TokenValidationException.class, () -> {
			offlineTokenValidationService.validateTokenHeader(header);
		});
		assertTrue(exception.getMessage().contains("JWK invalid!"));
	}

	@Test
	public void testValidateTokenHeader_missingHeaderClaim() {
		JsonObject header = Json.createObjectBuilder().add("alg", "123").build();
		TokenValidationException exception = assertThrows(TokenValidationException.class, () -> {
			offlineTokenValidationService.validateTokenHeader(header);
		});
		assertTrue(exception.getMessage().contains("Header invalid!"));
	}

	@Test
	public void testValidateTokenHeader_invalidCombination() {
		header = Json.createObjectBuilder().add("alg", "abc").add("kid", "456").build();
		assertFalse(offlineTokenValidationService.validateTokenHeader(header));
	}

	@Test
	public void testValidateTokenHeader_validHeader() {
		assertTrue(offlineTokenValidationService.validateTokenHeader(header));
	}

	@Test
	public void testValidateGeneralInfo_missingClaim() {
		JsonObject payload = Json.createObjectBuilder().add("test", "test").build();
		assertFalse(offlineTokenValidationService.validateGeneralInfo(payload));
	}

	@Test
	public void testValidateGeneralInfo_invalidIss() {
		JsonObject payload = mockService.createPayload(Arrays.asList(PayloadOptions.ISS_INVALID));
		assertFalse(offlineTokenValidationService.validateGeneralInfo(payload));
	}

	@Test
	public void testValidateGeneralInfo_expiredToken() {
		JsonObject payload = mockService.createPayload(Arrays.asList(PayloadOptions.EXP_INVALID));
		assertFalse(offlineTokenValidationService.validateGeneralInfo(payload));
	}

	@Test
	public void testValidateGeneralInfo_validPayload() {
		JsonObject payload = mockService.createPayload(new ArrayList<PayloadOptions>());
		assertTrue(offlineTokenValidationService.validateGeneralInfo(payload));
	}

	@Test
	public void testValidateSignature_invalidSignature() {
		try (MockedStatic<JwtUtil> mockStatic = Mockito.mockStatic(JwtUtil.class)) {
			mockStatic.when(() -> JwtUtil.decodeHeader(null)).thenReturn(header);
			mockStatic.when(() -> JwtUtil.decodePayload(null)).thenReturn(mockService.createPayload(
				Arrays.asList(PayloadOptions.ROLE, PayloadOptions.SCOPE, PayloadOptions.SCOPE_NOT_EXIST)));
			when(signatureVerifier.validateTokenSignature(null)).thenReturn(false);
			assertFalse(offlineTokenValidationService.validateToken(tokenValidationRequest));
		}
	}

	@Test
	public void testValidateSignature_validSignature() {
		try (MockedStatic<JwtUtil> mockStatic = Mockito.mockStatic(JwtUtil.class)) {
			mockStatic.when(() -> JwtUtil.decodeHeader(null)).thenReturn(header);
			mockStatic.when(() -> JwtUtil.decodePayload(null)).thenReturn(mockService.createPayload(
				Arrays.asList(PayloadOptions.ROLE, PayloadOptions.SCOPE, PayloadOptions.SCOPE_NOT_EXIST)));
			when(signatureVerifier.validateTokenSignature(null)).thenReturn(true);
			assertTrue(offlineTokenValidationService.validateToken(tokenValidationRequest));
		}
	}

}
