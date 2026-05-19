package de.cidaas.quarkus.extension.runtime;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;

import de.cidaas.quarkus.extension.token.validation.MockService;
import de.cidaas.quarkus.extension.token.validation.TokenValidationRequest;
import de.cidaas.quarkus.extension.token.validation.ValidationMode;
import de.cidaas.quarkus.extension.token.validation.ValidationResult;
import io.quarkus.test.InjectMock;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;

@QuarkusTest
public class CidaasServiceTest {

	@InjectMock
	TokenValidationEngine validationEngine;

	@Inject
	CidaasService cidaasService;

	@Inject
	MockService mockService;

	@Test
	public void testValidateTokenDelegatesToEngine() {
		TokenValidationRequest request = mockService.createValidationRequest();
		when(validationEngine.validate(eq(request), any(), eq(""), eq(false), eq(ValidationMode.OFF),
				eq(ValidationMode.OFF), eq(ValidationMode.REPORT)))
				.thenReturn(ValidationResult.valid(null));
		assertTrue(cidaasService.validateToken(request));
	}
}
