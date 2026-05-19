package de.cidaas.quarkus.extension.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Validates a Personal Access Token via PAT introspection
 * ({@code /accesspass-srv/passes/pat/introspect}), aligned with Go {@code pkg/patinterceptor}.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface PatValidation {
	String baseUrl() default "";

	String[] roles() default {};

	GroupAllowed[] groups() default {};

	String[] scopes() default {};

	boolean strictRoleValidation() default false;

	boolean strictGroupValidation() default false;

	boolean strictScopeValidation() default false;

	boolean strictValidation() default false;
}
