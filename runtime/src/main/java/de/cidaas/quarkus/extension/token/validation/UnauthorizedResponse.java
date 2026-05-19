package de.cidaas.quarkus.extension.token.validation;

/**
 * Cidaas-standard error body (aligned with go interceptor v3+).
 */
public class UnauthorizedResponse {
	private boolean success;
	private int status;
	private String errorMsg;
	private String code;

	public UnauthorizedResponse() {
		this.success = false;
		this.status = 401;
		this.errorMsg = "Unauthorized";
		this.code = "401";
	}

	public boolean isSuccess() {
		return success;
	}

	public int getStatus() {
		return status;
	}

	public String getErrorMsg() {
		return errorMsg;
	}

	public String getCode() {
		return code;
	}
}
