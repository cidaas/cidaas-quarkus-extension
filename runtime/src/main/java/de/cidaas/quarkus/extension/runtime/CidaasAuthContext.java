package de.cidaas.quarkus.extension.runtime;

import de.cidaas.quarkus.extension.token.validation.TokenData;
import jakarta.enterprise.context.RequestScoped;

@RequestScoped
public class CidaasAuthContext {
	private TokenData tokenData;

	public TokenData getTokenData() {
		return tokenData;
	}

	public void setTokenData(TokenData tokenData) {
		this.tokenData = tokenData;
	}
}
