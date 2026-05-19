package de.cidaas.quarkus.extension.token.validation;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

class ClaimValidatorTest {

	@Test
	void looseScopeMatch() {
		TokenValidationRequest req = new TokenValidationRequest();
		req.setScopes(List.of("profile", "email"));
		assertTrue(ClaimValidator.validate(req, List.of("profile"), List.of(), List.of()));
	}

	@Test
	void strictScopeRequiresAll() {
		TokenValidationRequest req = new TokenValidationRequest();
		req.setScopes(List.of("profile", "email"));
		req.setStrictScopeValidation(true);
		assertFalse(ClaimValidator.validate(req, List.of("profile"), List.of(), List.of()));
		assertTrue(ClaimValidator.validate(req, List.of("profile", "email"), List.of(), List.of()));
	}

	@Test
	void looseRoleMatch() {
		TokenValidationRequest req = new TokenValidationRequest();
		req.setRoles(List.of("ADMIN", "USER"));
		assertTrue(ClaimValidator.validate(req, List.of(), List.of("ADMIN"), List.of()));
	}

	@Test
	void strictRoleRequiresAll() {
		TokenValidationRequest req = new TokenValidationRequest();
		req.setRoles(List.of("ADMIN", "USER"));
		req.setStrictRoleValidation(true);
		assertFalse(ClaimValidator.validate(req, List.of(), List.of("ADMIN"), List.of()));
		assertTrue(ClaimValidator.validate(req, List.of(), List.of("ADMIN", "USER"), List.of()));
	}

	@Test
	void groupTypeStrictMatch() {
		TokenValidationRequest req = new TokenValidationRequest();
		Group group = new Group("g1", "USER", List.of("r1", "r2"), true, true);
		req.setGroups(List.of(group));
		req.setStrictGroupValidation(true);

		GroupDetails tokenGroup = new GroupDetails("g1", "USER", List.of("r1", "r2"));
		assertTrue(ClaimValidator.validate(req, List.of(), List.of(), List.of(tokenGroup)));

		GroupDetails wrongType = new GroupDetails("g1", "ADMIN", List.of("r1", "r2"));
		assertFalse(ClaimValidator.validate(req, List.of(), List.of(), List.of(wrongType)));
	}

	@Test
	void groupLooseMatchByIdOrType() {
		TokenValidationRequest req = new TokenValidationRequest();
		Group group = new Group("g1", "USER", List.of("r1"), false, false);
		req.setGroups(List.of(group));

		GroupDetails byType = new GroupDetails("other", "USER", List.of("r1"));
		assertTrue(ClaimValidator.validate(req, List.of(), List.of(), List.of(byType)));
	}

	@Test
	void strictValidationRequiresRoleAndScope() {
		TokenValidationRequest req = new TokenValidationRequest();
		req.setScopes(List.of("profile"));
		req.setRoles(List.of("ADMIN"));
		req.setStrictValidation(true);

		assertFalse(ClaimValidator.validate(req, List.of("profile"), List.of(), List.of()));
		assertTrue(ClaimValidator.validate(req, List.of("profile"), List.of("ADMIN"), List.of()));
	}
}
