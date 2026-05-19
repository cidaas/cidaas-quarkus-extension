package de.cidaas.quarkus.extension.token.validation;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonString;
import jakarta.json.JsonValue;

public class IntrospectResponse {
	private String iss;
	private boolean active;
	private List<String> aud = new ArrayList<>();
	private String sub;
	private List<String> roles = new ArrayList<>();
	private List<String> scopes = new ArrayList<>();
	private List<GroupDetails> groups = new ArrayList<>();
	private String clientId;
	private Map<String, String> cnf = new HashMap<>();

	public static IntrospectResponse fromJson(JsonObject json) {
		IntrospectResponse r = new IntrospectResponse();
		r.iss = json.getString("iss", "");
		r.active = json.getBoolean("active", false);
		r.sub = json.getString("sub", "");
		r.clientId = json.getString("client_id", "");
		r.aud = readAudience(json);
		String scopeClaim = json.containsKey("scope") && !json.isNull("scope") ? json.getString("scope", null) : null;
		List<String> legacyScopes = readStringArray(json, "scopes");
		r.scopes = ScopeNormalizer.normalizeEffectiveScopes(scopeClaim, legacyScopes);
		r.roles = readStringArray(json, "roles");
		r.groups = readGroups(json);
		if (json.containsKey("cnf") && !json.isNull("cnf")) {
			JsonObject cnfObj = json.getJsonObject("cnf");
			for (String key : cnfObj.keySet()) {
				if (!cnfObj.isNull(key)) {
					r.cnf.put(key, cnfObj.getString(key));
				}
			}
		}
		return r;
	}

	public TokenData toTokenData() {
		TokenData data = new TokenData();
		data.setSub(sub);
		data.setAud(aud);
		data.setScopes(scopes);
		data.setGroups(groups);
		data.setClientId(ClientIdResolver.resolve(clientId, aud));
		return data;
	}

	private static List<String> readAudience(JsonObject json) {
		if (!json.containsKey("aud") || json.isNull("aud")) {
			return List.of();
		}
		JsonValue aud = json.get("aud");
		if (aud.getValueType() == JsonValue.ValueType.STRING) {
			return List.of(((JsonString) aud).getString());
		}
		if (aud.getValueType() == JsonValue.ValueType.ARRAY) {
			return aud.asJsonArray().getValuesAs(JsonString::getString);
		}
		return List.of();
	}

	private static List<String> readStringArray(JsonObject json, String key) {
		if (!json.containsKey(key) || json.isNull(key)) {
			return List.of();
		}
		return json.getJsonArray(key).getValuesAs(JsonString::getString);
	}

	private static List<GroupDetails> readGroups(JsonObject json) {
		List<GroupDetails> result = new ArrayList<>();
		if (!json.containsKey("groups") || json.isNull("groups")) {
			return result;
		}
		JsonArray groups = json.getJsonArray("groups");
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

	public String getIss() {
		return iss;
	}

	public boolean isActive() {
		return active;
	}

	public List<String> getAud() {
		return aud;
	}

	public String getSub() {
		return sub;
	}

	public List<String> getRoles() {
		return roles;
	}

	public List<String> getScopes() {
		return scopes;
	}

	public List<GroupDetails> getGroups() {
		return groups;
	}

	public Map<String, String> getCnf() {
		return cnf;
	}
}
