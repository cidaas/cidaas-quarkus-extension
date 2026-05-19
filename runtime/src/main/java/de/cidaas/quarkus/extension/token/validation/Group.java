package de.cidaas.quarkus.extension.token.validation;

import java.util.List;

public class Group {
	private String groupId;
	private String groupType;
	private List<String> roles;
	private boolean strictRoleValidation;
	private boolean strictValidation;

	public Group(String groupId, List<String> roles) {
		this(groupId, "", roles, false, false);
	}

	public Group(String groupId, List<String> roles, boolean strictRoleValidation) {
		this(groupId, "", roles, strictRoleValidation, false);
	}

	public Group(String groupId, String groupType, List<String> roles, boolean strictRoleValidation,
			boolean strictValidation) {
		this.groupId = groupId;
		this.groupType = groupType != null ? groupType : "";
		this.roles = roles;
		this.strictRoleValidation = strictRoleValidation;
		this.strictValidation = strictValidation;
	}

	public String getGroupId() {
		return groupId;
	}

	public String getGroupType() {
		return groupType;
	}

	public List<String> getRoles() {
		return roles;
	}

	public boolean isStrictRoleValidation() {
		return strictRoleValidation;
	}

	public boolean isStrictValidation() {
		return strictValidation;
	}
}
