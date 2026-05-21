# cidaas Quarkus Extension

Quarkus Extension to integrate cidaas seamlessly to Java Project, which used Quarkus Framework.

## Requirement

Ensure your project is using Quarkus Framework v3.35.0 or later (Java 21 recommended) and the Quarkus REST extension instead of RESTEasy Classic or RESTEasy Reactive, to use cidaas-quarkus-extension v3.0 and later.

## Installation

From Maven pom.xml, add the following dependency:

```java
<dependency>
    <groupId>de.cidaas</groupId>
    <artifactId>cidaas-quarkus-extension</artifactId>
    <version>{EXTENSION_VERSION}</version>
</dependency>
```

## Initialisation

After adding the extension dependency, configure your cidaas instance in `application.properties` (aligned with the public Go interceptor v4 external model):

```properties
de.cidaas.quarkus.extension.base-url=https://your-instance.cidaas.de
de.cidaas.quarkus.extension.client-id=<app_client_id>
de.cidaas.quarkus.extension.client-secret=<app_client_secret>
```

`client-id` and `client-secret` are required for online introspection. For offline validation only, `base-url` is sufficient (JWKS is resolved via OpenID discovery).

The legacy key `de.cidaas.quarkus.extension.runtime.CidaasClient/mp-rest/url`, which has been used up until `v2.1.0`, is still accepted as a fallback for `base-url`.

Optional validation modes (defaults match public Go v4: DPoP/mTLS off, access-token type report-only):

```properties
de.cidaas.quarkus.extension.dpop-validation-mode=off
de.cidaas.quarkus.extension.mtls-validation-mode=off
de.cidaas.quarkus.extension.access-token-type-validation-mode=report
```

Allowed values for each mode: `off`, `report`, `enforce`.

By default, the JWKS list is cached for offline validation. The refresh interval can be overridden with:

```java
de.cidaas.quarkus.extension.cache-refresh-rate=216000s
```

the above example will refresh jwk list each 6 hour. This Configuration is optional, and the default value is 86400s (1 day).

To use Address Validation feature, apicid & apikey are need to be provided. The .env file could be used for storing and using credentials in development mode. The .env file looks like the following:

```java
de.cidaas.quarkus.extension.address.validation.apicid=<apicid>
de.cidaas.quarkus.extension.address.validation.apikey=<apikey>
```

## Usage

### Token Validation

To do token validation either by using cidaas introspection endpoint or using offline token validation, add the @TokenValidation annotation to the function. The annotation support the following optional members:

| Name                  | Description                                                                                                                                                                                                         | Default Value |
|-----------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------|
| roles                 | List of roles which are allowed to access secured api                                                                                                                                                               | Empty Array   |
| groups                | List of groups which are allowed to access secured api                                                                                                                                                              | Empty Array   |
| scopes                | List of scopes which are allowed to access secured api                                                                                                                                                              | Empty Array   |
| strictRoleValidation  | If true, user will need all roles from the list to access api. By default, user only need 1 of the roles                                                                                                            | false         |
| strictGroupValidation | If true, user will need all groups from the list to access api. By default, user only need 1 of the groups                                                                                                          | false         |
| strictScopeValidation | If true, user will need all scopes from the list to access api. By default, user only need 1 of the scopes                                                                                                          | false         |
| strictValidation      | If true, user will need to have each of defined validation (roles, groups and/or scopes). E.g. valid roles & valid scopes. By default, user will be able to access api only with 1 validation e.g. valid roles only | false         |
| offlineValidation      | If true, token will be validated locally using offline token validation, without calling introspection endpoint | false         |
| tokenTypeHint         | described which type of token is currently being validated. e.g. access_token                                                                                                                                       | Empty String  |
| baseUrl               | Override instance base URL for this endpoint (empty = global config)                                                                                                              | Empty String  |
| dpopValidationMode    | Per-endpoint DPoP mode: `off`, `report`, `enforce` (empty = global config)                                                                                                          | Empty String  |
| mtlsValidationMode  | Per-endpoint mTLS binding mode: `off`, `report`, `enforce` (empty = global config)                                                                                                  | Empty String  |

Unauthorized requests receive a JSON body with `errorMsg` (HTTP 401), matching the public Go interceptor.

After successful validation, inject `CidaasAuthContext` to read parsed token claims as `TokenData`:

```java
@Inject
CidaasAuthContext authContext;

@GET
@Path("/me")
@TokenValidation
public String me() {
    return authContext.getTokenData().getSub();
}
```

For programmatic validation without the filter, inject `TokenVerifier` (Go `verify.ByTokenRequest` equivalent).

### Personal Access Token (PAT)

Use `@PatValidation` on a resource method to validate PATs via `/accesspass-srv/passes/pat/introspect`. Members are the same as `@TokenValidation` for roles, groups, and scopes (without offline/DPoP/mTLS options).

to validate groups, @GroupAllowed Annotation(s) have to be added. It has the following member:

| Name                 | Description                                                                                                          | is required                |
|----------------------|----------------------------------------------------------------------------------------------------------------------|----------------------------|
| id                   | group id                                                                                                             | yes                        |
| groupType            | optional group type filter (empty = match by id only)                                                                | no                         |
| roles                | List of group roles, which are allowed to access secured api                                                         | yes                        |
| strictRoleValidation | If true, user will need all roles from the group roles list to access api. By default, user only need 1 of the roles | no, default value is false |
| strictValidation     | If true, all configured group roles must match (AND); otherwise any match suffices (OR)                            | no, default value is false |

Examples of function being secured with cidaas quarkus extension looks like the following:

* User need only to be authenticated, without having any roles, groups or scopes to access the api
```java
@GET
@Path("/protected")
@Produces(MediaType.TEXT_PLAIN)
@TokenValidation
public String helloProtected() {
    return "Hello from protected api";
}
```

* User need to have one of the "role1" or "role2" role to access the api
```java
@GET
@Path("/protected")
@Produces(MediaType.TEXT_PLAIN)
@TokenValidation(roles = {"role1", "role2"})
public String helloProtected() {
    return "Hello from protected api";
}
```

* User need to either have one of the "role1" or "role2" role to access the api, or both "scope1" and "scope2" scopes
```java
@GET
@Path("/protected")
@Produces(MediaType.TEXT_PLAIN)
@TokenValidation(
    roles = {"role1", "role2"},
    scopes = { "scope1", "scope2" },
    strictScopeValidation = true
)
public String helloProtected() {
    return "Hello from protected api";
}
```

* User need to have every roles and scopes to access the api
```java
@GET
@Path("/protected")
@Produces(MediaType.TEXT_PLAIN)
@TokenValidation(
    roles = {"role1", "role2"},
    scopes = { "scope1", "scope2" },
    strictValidation = true,
    strictRoleValidation = true,
    strictScopeValidation = true
)
public String helloProtected() {
    return "Hello from protected api";
}
```

* User need to be either in the group with roles, or have one of the scopes to access the api
```java
@GET
@Path("/protected")
@Produces(MediaType.TEXT_PLAIN)
@TokenValidation(
    groups = {
        @GroupAllowed(id="groupId", roles = { "groupRole" }),
    },
    scopes = { "scope1", "scope2" },
)
public String helloProtected() {
    return "Hello from protected api";
}
```

* User need to be both in the group1 with one of the  "groupRole1" or "groupRole2" role, and in the group2 with both "groupRole3" and "groupRole4" roles to access the api
```java
@GET
@Path("/protected")
@Produces(MediaType.TEXT_PLAIN)
@TokenValidation(
    groups = {
        @GroupAllowed(
            id="group1", 
            roles = { "groupRole1", "groupRole2" }
        ),
        @GroupAllowed(
            id="group2", 
            roles = { "groupRole3", "groupRole4" },
            strictRoleValidation=true 
        ),
    },
    strictGroupValidation = true,
)
public String helloProtected() {
    return "Hello from protected api";
}
```

* User need to have one of the "role1" or "role2" role to access the api, and want to use offline token validation instead of calling introspection endpoint
```java
@GET
@Path("/protected")
@Produces(MediaType.TEXT_PLAIN)
@TokenValidation(
    roles = {"role1", "role2"},
    offlineValidation = true
)
public String helloProtected() {
    return "Hello from protected api";
}
```

### Address Validation

To do address & email validation, inject AddressValidationService to the class which will be calling the validation.

Examples of address validation usage looks like the following:

* Address Validation
```java
@Inject
AddressValidationService addressValidationService;

@GET
@Path("/validate-address")
@Produces(MediaType.TEXT_PLAIN)
public String validateValidAddress() {
    AddressValidationRequest request = new AddressValidationRequest();
    request.setStreet("examplsstr.");
    request.setHouseNumber("1");
    request.setZipCode("11111");
    request.setCity("exampleCity");
    
    AddressValidationResult result = addressValidationService.validateAddress(request);
    return "Address Validation Result is " + result.getResulttext();
}
```

* Email Validation
```java
@Inject
AddressValidationService addressValidationService;

@GET
@Path("/validate-email")
@Produces(MediaType.TEXT_PLAIN)
public String validateValidAddress() {
    boolean result = addressValidationService.validateEmail("example.email@domain.com");
	return "Email Validation Result is " + result;
}
```