package de.cidaas.quarkus.extension.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import de.cidaas.quarkus.extension.token.validation.TokenValidationException;

class CidaasInstanceServiceTest {

	MockCidaasServer mockServer;
	CidaasInstanceService instanceService;

	@BeforeEach
	void setUp() throws Exception {
		mockServer = MockCidaasServer.start();
		instanceService = new CidaasInstanceService();
	}

	@AfterEach
	void tearDown() {
		mockServer.close();
	}

	@Test
	void loadsOpenIdConfigurationAndJwks() {
		CidaasInstanceDetails details = instanceService.getInstanceDetails(mockServer.baseUrl);

		assertEquals(mockServer.baseUrl, details.getIssuer());
		assertEquals(mockServer.baseUrl + "/token-srv/introspect", details.getIntrospectionEndpoint());
		assertNotNull(details.getJwks());
	}

	@Test
	void cachesInstanceDetailsLocally() {
		CidaasInstanceDetails first = instanceService.getInstanceDetails(mockServer.baseUrl);
		CidaasInstanceDetails second = instanceService.getInstanceDetails(mockServer.baseUrl);

		assertSame(first, second);
	}

	@Test
	void getJwksUsesInstanceDiscovery() {
		assertNotNull(instanceService.getJwks(mockServer.baseUrl).getJsonArray("keys"));
	}

	@Test
	void failsWhenOpenIdConfigurationUnavailable() throws Exception {
		com.sun.net.httpserver.HttpServer broken = com.sun.net.httpserver.HttpServer
				.create(new java.net.InetSocketAddress("127.0.0.1", 0), 0);
		int port = broken.getAddress().getPort();
		String brokenUrl = "http://127.0.0.1:" + port;
		broken.createContext("/.well-known/openid-configuration",
				exchange -> MockCidaasServer.errorResponse(exchange, 503));
		broken.start();
		try {
			assertThrows(TokenValidationException.class, () -> instanceService.getInstanceDetails(brokenUrl));
		} finally {
			broken.stop(0);
		}
	}
}
