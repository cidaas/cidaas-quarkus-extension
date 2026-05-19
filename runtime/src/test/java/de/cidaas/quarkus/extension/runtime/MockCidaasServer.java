package de.cidaas.quarkus.extension.runtime;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;

/**
 * Minimal HTTP stand-in for cidaas OpenID discovery, JWKS, and token introspection.
 */
final class MockCidaasServer implements AutoCloseable {

	final HttpServer server;
	final String baseUrl;
	final AtomicReference<String> lastIntrospectBody = new AtomicReference<>();
	volatile IntrospectHandler introspectHandler;

	MockCidaasServer() throws IOException {
		server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		int port = server.getAddress().getPort();
		baseUrl = "http://127.0.0.1:" + port;
		introspectHandler = (body, exchange) -> activeResponse(exchange, baseUrl, "user-1");
		server.createContext("/.well-known/openid-configuration", this::handleOpenId);
		server.createContext("/.well-known/jwks.json", this::handleJwks);
		server.createContext("/token-srv/introspect", this::handleIntrospect);
		server.createContext("/accesspass-srv/passes/pat/introspect", this::handleIntrospect);
		server.start();
	}

	static MockCidaasServer start() throws IOException {
		return new MockCidaasServer();
	}

	void handleOpenId(HttpExchange exchange) throws IOException {
		if (!"GET".equals(exchange.getRequestMethod())) {
			exchange.sendResponseHeaders(405, -1);
			return;
		}
		String body = """
				{
				  "issuer":"%s",
				  "introspection_endpoint":"%s/token-srv/introspect",
				  "jwks_uri":"%s/.well-known/jwks.json"
				}
				""".formatted(baseUrl, baseUrl, baseUrl);
		writeJson(exchange, 200, body);
	}

	void handleJwks(HttpExchange exchange) throws IOException {
		if (!"GET".equals(exchange.getRequestMethod())) {
			exchange.sendResponseHeaders(405, -1);
			return;
		}
		writeJson(exchange, 200, "{\"keys\":[]}");
	}

	void handleIntrospect(HttpExchange exchange) throws IOException {
		if (!"POST".equals(exchange.getRequestMethod())) {
			exchange.sendResponseHeaders(405, -1);
			return;
		}
		String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
		lastIntrospectBody.set(body);
		introspectHandler.handle(body, exchange);
	}

	static void activeResponse(HttpExchange exchange, String issuer, String sub) throws IOException {
		String body = """
				{
				  "active":true,
				  "iss":"%s",
				  "sub":"%s",
				  "client_id":"test-client",
				  "scopes":["profile","email"],
				  "roles":["ADMIN"],
				  "groups":[{"groupId":"g1","groupType":"USER","roles":["r1","r2"]}]
				}
				""".formatted(issuer, sub);
		writeJson(exchange, 200, body);
	}

	static void inactiveResponse(HttpExchange exchange) throws IOException {
		writeJson(exchange, 200, "{\"active\":false}");
	}

	static void errorResponse(HttpExchange exchange, int status) throws IOException {
		exchange.sendResponseHeaders(status, -1);
		exchange.close();
	}

	static void activeResponseWithCnf(HttpExchange exchange, String issuer, String sub, String jkt, String x5tS256)
			throws IOException {
		StringBuilder cnf = new StringBuilder("{");
		if (jkt != null && !jkt.isBlank()) {
			cnf.append("\"jkt\":\"").append(jkt).append("\"");
		}
		if (x5tS256 != null && !x5tS256.isBlank()) {
			if (cnf.length() > 1) {
				cnf.append(',');
			}
			cnf.append("\"x5t#S256\":\"").append(x5tS256).append("\"");
		}
		cnf.append('}');
		String body = """
				{
				  "active":true,
				  "iss":"%s",
				  "sub":"%s",
				  "cnf":%s
				}
				""".formatted(issuer, sub, cnf);
		writeJson(exchange, 200, body);
	}

	static JsonObject parseBody(String body) {
		try (JsonReader reader = Json.createReader(new java.io.StringReader(body))) {
			return reader.readObject();
		}
	}

	private static void writeJson(HttpExchange exchange, int status, String body) throws IOException {
		byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
		exchange.getResponseHeaders().add("Content-Type", "application/json");
		exchange.sendResponseHeaders(status, bytes.length);
		try (OutputStream os = exchange.getResponseBody()) {
			os.write(bytes);
		}
	}

	@Override
	public void close() {
		server.stop(0);
	}

	@FunctionalInterface
	interface IntrospectHandler {
		void handle(String body, HttpExchange exchange) throws IOException;
	}
}
