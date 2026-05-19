package de.cidaas.quarkus.extension.runtime;

import java.lang.reflect.Method;
import java.util.Optional;

import org.jboss.resteasy.reactive.RestResponse;
import org.jboss.resteasy.reactive.server.ServerRequestFilter;

import de.cidaas.quarkus.extension.annotation.PatValidation;
import de.cidaas.quarkus.extension.token.validation.TokenValidationMapper;
import de.cidaas.quarkus.extension.token.validation.TokenValidationRequest;
import de.cidaas.quarkus.extension.token.validation.UnauthorizedResponse;
import de.cidaas.quarkus.extension.token.validation.ValidationResult;
import jakarta.inject.Inject;
import jakarta.json.Json;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

public class PatAuthFilter {

	@Inject
	ResourceInfo resourceInfo;

	@Inject
	TokenValidationEngine validationEngine;

	@Inject
	CidaasAuthContext authContext;

	@ServerRequestFilter
	public Optional<RestResponse<?>> filter(ContainerRequestContext requestContext) {
		if (resourceInfo == null || resourceInfo.getResourceMethod() == null) {
			return Optional.empty();
		}
		Method method = resourceInfo.getResourceMethod();
		PatValidation patValidation = method.getAnnotation(PatValidation.class);
		if (patValidation == null) {
			return Optional.empty();
		}

		CidaasRequestMetadata metadata = CidaasRequestMetadata.from(requestContext);
		if (metadata.getAccessToken() == null || metadata.getAccessToken().isBlank()) {
			return Optional.of(unauthorized());
		}

		TokenValidationRequest request = mapPatRequest(metadata.getAccessToken(), patValidation);
		ValidationResult result = validationEngine.validatePat(request, metadata, patValidation.baseUrl());
		if (!result.isValid()) {
			return Optional.of(unauthorized());
		}
		authContext.setTokenData(result.getTokenData());
		return Optional.empty();
	}

	private TokenValidationRequest mapPatRequest(String token, PatValidation patValidation) {
		TokenValidationRequest request = new TokenValidationRequest();
		request.setToken(token);
		request.setToken_type_hint("pat");
		if (patValidation.roles() != null) {
			request.setRoles(java.util.Arrays.asList(patValidation.roles()));
		}
		if (patValidation.scopes() != null) {
			request.setScopes(java.util.Arrays.asList(patValidation.scopes()));
		}
		if (patValidation.groups() != null) {
			request.setGroups(TokenValidationMapper.mapGroups(patValidation.groups()));
		}
		request.setStrictRoleValidation(patValidation.strictRoleValidation());
		request.setStrictGroupValidation(patValidation.strictGroupValidation());
		request.setStrictScopeValidation(patValidation.strictScopeValidation());
		request.setStrictValidation(patValidation.strictValidation());
		return request;
	}

	private RestResponse<?> unauthorized() {
		UnauthorizedResponse err = new UnauthorizedResponse();
		String body = Json.createObjectBuilder()
				.add("success", err.isSuccess())
				.add("status", err.getStatus())
				.add("errorMsg", err.getErrorMsg())
				.add("code", err.getCode())
				.build()
				.toString();
		return RestResponse.ResponseBuilder
				.create(Response.Status.UNAUTHORIZED, body)
				.header("Content-Type", MediaType.APPLICATION_JSON + ";charset=utf-8")
				.header("X-Content-Type-Options", "nosniff")
				.build();
	}
}
