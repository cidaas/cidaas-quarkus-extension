package de.cidaas.quarkus.extension.token.validation;

import java.util.ArrayList;
import java.util.List;

import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonString;
import jakarta.json.JsonValue;

public final class JwtClaimsReader {

	private JwtClaimsReader() {
	}

	public static List<String> readScopes(JsonObject payload) {
		String scopeClaim = payload.containsKey("scope") && !payload.isNull("scope")
				? payload.getString("scope", null)
				: null;
		List<String> legacy = readStringArray(payload, "scopes");
		return ScopeNormalizer.normalizeEffectiveScopes(scopeClaim, legacy);
	}

	public static List<String> readRoles(JsonObject payload) {
		return readStringArray(payload, "roles");
	}

	public static List<GroupDetails> readGroups(JsonObject payload) {
		List<GroupDetails> result = new ArrayList<>();
		if (!payload.containsKey("groups") || payload.isNull("groups")) {
			return result;
		}
		JsonArray groups = payload.getJsonArray("groups");
		for (int i = 0; i < groups.size(); i++) {
			JsonObject g = groups.getJsonObject(i);
			String groupId = g.getString("groupId", "");
			String groupType = g.getString("groupType", "");
			List<String> roles = new ArrayList<>();
			if (g.containsKey("roles") && !g.isNull("roles")) {
				roles = g.getJsonArray("roles").getValuesAs(JsonString::getString);
			}
			result.add(new GroupDetails(groupId, groupType, roles));
		}
		return result;
	}

	public static List<String> readAudience(JsonObject payload) {
		if (!payload.containsKey("aud") || payload.isNull("aud")) {
			return List.of();
		}
		JsonValue aud = payload.get("aud");
		if (aud.getValueType() == JsonValue.ValueType.STRING) {
			return List.of(((JsonString) aud).getString());
		}
		if (aud.getValueType() == JsonValue.ValueType.ARRAY) {
			return aud.asJsonArray().getValuesAs(JsonString::getString);
		}
		return List.of();
	}

	public static String readCnfJkt(JsonObject payload) {
		if (!payload.containsKey("cnf") || payload.isNull("cnf")) {
			return "";
		}
		JsonObject cnf = payload.getJsonObject("cnf");
		return cnf.getString("jkt", "").trim();
	}

	public static String readCnfX5tS256(JsonObject payload) {
		if (!payload.containsKey("cnf") || payload.isNull("cnf")) {
			return "";
		}
		JsonObject cnf = payload.getJsonObject("cnf");
		return cnf.getString("x5t#S256", "").trim();
	}

	private static List<String> readStringArray(JsonObject payload, String key) {
		if (!payload.containsKey(key) || payload.isNull(key)) {
			return List.of();
		}
		return payload.getJsonArray(key).getValuesAs(JsonString::getString);
	}
}
