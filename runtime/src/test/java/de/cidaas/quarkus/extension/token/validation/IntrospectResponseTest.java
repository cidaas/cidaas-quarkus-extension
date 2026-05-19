package de.cidaas.quarkus.extension.token.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import jakarta.json.Json;

class IntrospectResponseTest {

	@Test
	void parsesScopeStringAndScopesArray() {
		var json = Json.createObjectBuilder()
				.add("active", true)
				.add("iss", "https://example.com")
				.add("sub", "u1")
				.add("scope", "openid profile")
				.add("scopes", Json.createArrayBuilder().add("email"))
				.build();

		IntrospectResponse response = IntrospectResponse.fromJson(json);

		assertTrue(response.getScopes().contains("openid"));
		assertTrue(response.getScopes().contains("profile"));
	}

	@Test
	void prefersScopeStringOverLegacyScopesArray() {
		var json = Json.createObjectBuilder()
				.add("active", true)
				.add("scope", "openid")
				.add("scopes", Json.createArrayBuilder().add("email"))
				.build();

		IntrospectResponse response = IntrospectResponse.fromJson(json);

		assertEquals(List.of("openid"), response.getScopes());
		assertFalse(response.getScopes().contains("email"));
	}

	@Test
	void usesLegacyScopesArrayWhenScopeClaimMissing() {
		var json = Json.createObjectBuilder()
				.add("active", true)
				.add("scopes", Json.createArrayBuilder().add("email").add("profile"))
				.build();

		assertEquals(List.of("email", "profile"), IntrospectResponse.fromJson(json).getScopes());
	}

	@Test
	void parsesAudienceAsStringAndArray() {
		var stringAud = Json.createObjectBuilder().add("active", true).add("aud", "client-a").build();
		assertEquals(List.of("client-a"), IntrospectResponse.fromJson(stringAud).getAud());

		var arrayAud = Json.createObjectBuilder()
				.add("active", true)
				.add("aud", Json.createArrayBuilder().add("a").add("b"))
				.build();
		assertEquals(List.of("a", "b"), IntrospectResponse.fromJson(arrayAud).getAud());
	}

	@Test
	void parsesCnfAndMapsToTokenData() {
		var json = Json.createObjectBuilder()
				.add("active", true)
				.add("sub", "user")
				.add("client_id", "")
				.add("aud", "fallback-client")
				.add("cnf", Json.createObjectBuilder()
						.add("jkt", "thumb")
						.add("x5t#S256", "cert"))
				.build();

		IntrospectResponse response = IntrospectResponse.fromJson(json);

		assertEquals("thumb", response.getCnf().get("jkt"));
		assertEquals("cert", response.getCnf().get("x5t#S256"));
		assertEquals("user", response.toTokenData().getSub());
		assertEquals("fallback-client", response.toTokenData().getClientId());
	}

	@Test
	void inactiveByDefault() {
		var json = Json.createObjectBuilder().add("sub", "x").build();
		assertFalse(IntrospectResponse.fromJson(json).isActive());
	}

	@Test
	void parsesGroupsWithGroupType() {
		var json = Json.createObjectBuilder()
				.add("active", true)
				.add("groups", Json.createArrayBuilder().add(Json.createObjectBuilder()
						.add("groupId", "g1")
						.add("groupType", "USER")
						.add("roles", Json.createArrayBuilder().add("r1"))))
				.build();

		List<GroupDetails> groups = IntrospectResponse.fromJson(json).getGroups();

		assertEquals(1, groups.size());
		assertEquals("g1", groups.get(0).getGroupId());
		assertEquals("USER", groups.get(0).getGroupType());
		assertEquals(List.of("r1"), groups.get(0).getRoles());
	}

	@Test
	void parsesGroupWithoutRoles() {
		var json = Json.createObjectBuilder()
				.add("active", true)
				.add("groups", Json.createArrayBuilder().add(Json.createObjectBuilder()
						.add("groupId", "g2")
						.add("groupType", "ADMIN")))
				.build();

		GroupDetails group = IntrospectResponse.fromJson(json).getGroups().get(0);
		assertEquals("g2", group.getGroupId());
		assertEquals("ADMIN", group.getGroupType());
		assertTrue(group.getRoles().isEmpty());
	}
}
