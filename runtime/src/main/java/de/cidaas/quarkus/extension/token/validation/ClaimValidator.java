package de.cidaas.quarkus.extension.token.validation;

import java.util.List;

/**
 * Port of go interceptor {@code checkScopesAndRolesAndGroups}.
 */
public final class ClaimValidator {

	private ClaimValidator() {
	}

	public static boolean validate(TokenValidationRequest request, List<String> tokenScopes,
			List<String> tokenRoles, List<GroupDetails> tokenGroups) {
		java.util.ArrayList<Boolean> checks = new java.util.ArrayList<>();

		if (hasElements(request.getScopes())) {
			checks.add(request.isStrictScopeValidation()
					? strictArrayValidate(request.getScopes(), tokenScopes)
					: looseArrayValidate(request.getScopes(), tokenScopes));
		}

		if (hasElements(request.getRoles())) {
			checks.add(request.isStrictRoleValidation()
					? strictArrayValidate(request.getRoles(), tokenRoles)
					: looseArrayValidate(request.getRoles(), tokenRoles));
		}

		if (hasElements(request.getGroups())) {
			checks.add(validateGroups(request, tokenGroups));
		}

		if (checks.isEmpty()) {
			return true;
		}
		if (request.isStrictValidation()) {
			return checks.stream().allMatch(Boolean::booleanValue);
		}
		return checks.stream().anyMatch(Boolean::booleanValue);
	}

	private static boolean validateGroups(TokenValidationRequest request, List<GroupDetails> tokenGroups) {
		int validGroupCount = 0;
		for (Group group : request.getGroups()) {
			GroupDetails matched = findMatchingGroup(group, tokenGroups);
			if (matched != null && groupRolesValid(group, matched)) {
				validGroupCount++;
			}
		}
		if (request.isStrictGroupValidation()) {
			return validGroupCount == request.getGroups().size();
		}
		return validGroupCount > 0;
	}

	private static GroupDetails findMatchingGroup(Group group, List<GroupDetails> tokenGroups) {
		for (GroupDetails tokenGroup : tokenGroups) {
			if (group.isStrictValidation()) {
				if (equalsIgnoreEmpty(group.getGroupId(), tokenGroup.getGroupId())
						&& equalsIgnoreEmpty(group.getGroupType(), tokenGroup.getGroupType())) {
					return tokenGroup;
				}
			} else {
				if (equalsIgnoreEmpty(group.getGroupId(), tokenGroup.getGroupId())
						|| equalsIgnoreEmpty(group.getGroupType(), tokenGroup.getGroupType())) {
					return tokenGroup;
				}
			}
		}
		return null;
	}

	private static boolean groupRolesValid(Group group, GroupDetails tokenGroup) {
		if (group.getRoles() == null || group.getRoles().isEmpty()) {
			return true;
		}
		return group.isStrictRoleValidation()
				? strictArrayValidate(group.getRoles(), tokenGroup.getRoles())
				: looseArrayValidate(group.getRoles(), tokenGroup.getRoles());
	}

	private static boolean equalsIgnoreEmpty(String a, String b) {
		if (a == null || a.isEmpty() || b == null || b.isEmpty()) {
			return false;
		}
		return a.equals(b);
	}

	static boolean strictArrayValidate(List<String> requested, List<String> tokenData) {
		if (requested == null || requested.isEmpty()) {
			return true;
		}
		if (tokenData == null) {
			tokenData = List.of();
		}
		int validCount = 0;
		for (String item : requested) {
			if (tokenData.contains(item)) {
				validCount++;
			}
		}
		return validCount == requested.size();
	}

	static boolean looseArrayValidate(List<String> requested, List<String> tokenData) {
		if (requested == null || requested.isEmpty()) {
			return true;
		}
		if (tokenData == null) {
			tokenData = List.of();
		}
		for (String item : requested) {
			if (tokenData.contains(item)) {
				return true;
			}
		}
		return false;
	}

	private static boolean hasElements(List<?> list) {
		return list != null && !list.isEmpty();
	}
}
