package de.cidaas.quarkus.extension.token.validation;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import jakarta.enterprise.context.RequestScoped;
import jakarta.json.Json;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;

@RequestScoped
public class MockService {
	String getToken() {
		return "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiVVNFUiIsImlzcyI6Iklzc3VlciIsImV4cCI6IjIwMjQtMDMtMTJUMTg6MzE6MjAuMzk2WiIsImlhdCI6IjIwMjQtMDMtMTJUMTI6MzE6MjAuMzk2WiJ9.ADYf1qQy11JJH3T2YPlXyDmIzggflj1O7zXKsUZc8fg";
	}

	public JsonObject createJwks() {
		JsonObject jwks = Json.createObjectBuilder()
				.add("keys",
						Json.createArrayBuilder().add(Json.createObjectBuilder().add("alg", "abc").add("kid", "def"))
								.add(Json.createObjectBuilder().add("alg", "123").add("kid", "456")))
				.build();
		return jwks;
	}

	JsonObject createHeader() {
		JsonObject header = Json.createObjectBuilder().add("alg", "123").add("kid", "456").build();
		return header;
	}

	JsonObject createPayload(List<PayloadOptions> options) {
		JsonObjectBuilder builder = Json.createObjectBuilder();

		if (options.contains(PayloadOptions.ISS_INVALID)) {
			builder.add("iss", "invalidUrl");
		} else {
			builder.add("iss", "https://mock.example.com");
		}

		if (options.contains(PayloadOptions.EXP_INVALID)) {
			builder.add("exp", Instant.now().getEpochSecond() - 3000);
		} else {
			builder.add("exp", Instant.now().getEpochSecond() + 3000);
		}

		if (options.contains(PayloadOptions.ROLE)) {
			if (options.contains(PayloadOptions.ROLE_NOT_EXIST)) {
				builder.add("roles", Json.createArrayBuilder().add("roleOther1").add("roleOther2"));
			} else if (options.contains(PayloadOptions.ROLE_NOT_COMPLETE)) {
				builder.add("roles", Json.createArrayBuilder().add("role1").add("roleOther"));
			} else {
				builder.add("roles", Json.createArrayBuilder().add("role1").add("role2"));
			}
		}

		if (options.contains(PayloadOptions.SCOPE)) {
			if (options.contains(PayloadOptions.SCOPE_NOT_EXIST)) {
				builder.add("scopes", Json.createArrayBuilder().add("scopeOther1").add("scopeOther2"));
			} else if (options.contains(PayloadOptions.SCOPE_NOT_COMPLETE)) {
				builder.add("scopes", Json.createArrayBuilder().add("scope1").add("scopeOther"));
			} else {
				builder.add("scopes", Json.createArrayBuilder().add("scope1").add("scope2"));
			}
		}

		if (options.contains(PayloadOptions.GROUPROLE)) {
			JsonArrayBuilder groupsBuilder = Json.createArrayBuilder();
			JsonObjectBuilder groupBuilder = Json.createObjectBuilder();
			groupBuilder.add("groupId", "group1");
			if (options.contains(PayloadOptions.GROUPROLE_NOT_EXIST)) {
				groupBuilder.add("roles", Json.createArrayBuilder().add("grouproleOther1").add("grouproleOther2"));
			} else if (options.contains(PayloadOptions.GROUPROLE_NOT_COMPLETE)) {
				groupBuilder.add("roles", Json.createArrayBuilder().add("grouprole1").add("grouproleOther"));
			} else {
				groupBuilder.add("roles", Json.createArrayBuilder().add("grouprole1").add("grouprole2"));
			}
			groupsBuilder.add(groupBuilder);
			builder.add("groups", groupsBuilder);
		}

		else if (options.contains(PayloadOptions.GROUP)) {
			if (options.contains(PayloadOptions.GROUP_NOT_EXIST)) {
				builder.add("groups",
						Json.createArrayBuilder()
								.add(Json.createObjectBuilder().add("groupId", "groupOther1").add("roles",
										Json.createArrayBuilder().add("grouprole1").add("grouprole2")))
								.add(Json.createObjectBuilder().add("groupId", "groupOther2").add("roles",
										Json.createArrayBuilder().add("grouprole3").add("grouprole4"))));
			} else if (options.contains(PayloadOptions.GROUP_NOT_COMPLETE)) {
				builder.add("groups",
						Json.createArrayBuilder()
								.add(Json.createObjectBuilder().add("groupId", "group1").add("roles",
										Json.createArrayBuilder().add("grouprole1").add("grouprole2")))
								.add(Json.createObjectBuilder().add("groupId", "groupOther2").add("roles",
										Json.createArrayBuilder().add("grouprole3").add("grouprole4"))));
			} else {
				builder.add("groups",
						Json.createArrayBuilder()
								.add(Json.createObjectBuilder().add("groupId", "group1").add("roles",
										Json.createArrayBuilder().add("grouprole1").add("grouprole2")))
								.add(Json.createObjectBuilder().add("groupId", "group2").add("roles",
										Json.createArrayBuilder().add("grouprole3").add("grouprole4"))));
			}
		}
		return builder.build();
	}

	public TokenValidationRequest createValidationRequest() {
		return createValidationRequest(
				Arrays.asList(ValidationOptions.ROLE, ValidationOptions.SCOPE, ValidationOptions.GROUP));
	}

	TokenValidationRequest createValidationRequest(List<ValidationOptions> options) {
		TokenValidationRequest result = new TokenValidationRequest();
		if (options.contains(ValidationOptions.ROLE)) {
			result.setRoles(Arrays.asList("role1", "role2"));
		}
		if (options.contains(ValidationOptions.SCOPE)) {
			result.setScopes(Arrays.asList("scope1", "scope2"));
		}
		if (options.contains(ValidationOptions.GROUP)) {
			boolean strictGrouproleValidation = (options.contains(ValidationOptions.GROUPROLE_STRICT));
			List<Group> groups = new ArrayList<>();
			groups.add(new Group("group1", Arrays.asList("grouprole1", "grouprole2"), strictGrouproleValidation));
			groups.add(new Group("group2", Arrays.asList("grouprole3", "grouprole4")));
			result.setGroups(groups);
		}
		result.setStrictRoleValidation(options.contains(ValidationOptions.ROLE_STRICT));
		result.setStrictGroupValidation(options.contains(ValidationOptions.GROUP_STRICT));
		result.setStrictScopeValidation(options.contains(ValidationOptions.SCOPE_STRICT));
		result.setStrictValidation(options.contains(ValidationOptions.VALIDATION_STRICT));
		return result;
	}

	enum PayloadOptions {
		ROLE, GROUP, GROUPROLE, SCOPE, ROLE_NOT_EXIST, GROUP_NOT_EXIST, GROUPROLE_NOT_EXIST, SCOPE_NOT_EXIST,
		ROLE_NOT_COMPLETE, GROUP_NOT_COMPLETE, GROUPROLE_NOT_COMPLETE, SCOPE_NOT_COMPLETE, ISS_INVALID, EXP_INVALID,
	}

	enum ValidationOptions {
		ROLE, GROUP, SCOPE, ROLE_STRICT, GROUP_STRICT, GROUPROLE_STRICT, SCOPE_STRICT, VALIDATION_STRICT
	}
}
