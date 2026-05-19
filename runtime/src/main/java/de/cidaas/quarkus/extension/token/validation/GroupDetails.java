package de.cidaas.quarkus.extension.token.validation;

import java.util.ArrayList;
import java.util.List;

public class GroupDetails {
	private String groupId;
	private String groupType;
	private List<String> roles = new ArrayList<>();

	public GroupDetails() {
	}

	public GroupDetails(String groupId, String groupType, List<String> roles) {
		this.groupId = groupId;
		this.groupType = groupType;
		this.roles = roles != null ? roles : new ArrayList<>();
	}

	public String getGroupId() {
		return groupId;
	}

	public void setGroupId(String groupId) {
		this.groupId = groupId;
	}

	public String getGroupType() {
		return groupType;
	}

	public void setGroupType(String groupType) {
		this.groupType = groupType;
	}

	public List<String> getRoles() {
		return roles;
	}

	public void setRoles(List<String> roles) {
		this.roles = roles != null ? roles : new ArrayList<>();
	}
}
