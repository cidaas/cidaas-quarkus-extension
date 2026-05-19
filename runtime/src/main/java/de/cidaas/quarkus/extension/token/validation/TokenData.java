package de.cidaas.quarkus.extension.token.validation;

import java.util.ArrayList;
import java.util.List;

public class TokenData {
	private String sub;
	private List<String> aud = new ArrayList<>();
	private List<String> scopes = new ArrayList<>();
	private List<GroupDetails> groups = new ArrayList<>();
	private String clientId;

	public String getSub() {
		return sub;
	}

	public void setSub(String sub) {
		this.sub = sub;
	}

	public List<String> getAud() {
		return aud;
	}

	public void setAud(List<String> aud) {
		this.aud = aud != null ? aud : new ArrayList<>();
	}

	public List<String> getScopes() {
		return scopes;
	}

	public void setScopes(List<String> scopes) {
		this.scopes = scopes != null ? scopes : new ArrayList<>();
	}

	public List<GroupDetails> getGroups() {
		return groups;
	}

	public void setGroups(List<GroupDetails> groups) {
		this.groups = groups != null ? groups : new ArrayList<>();
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}
}
