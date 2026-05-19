package de.cidaas.quarkus.extension.token.validation;

import java.io.StringReader;
import java.util.Base64;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;

public class JwtUtil {

	public static JsonObject decodeHeader(String accessToken) {
		String[] arr = accessToken.split("\\.", 3);
		if (arr.length < 2) {
			return null;
		}
		return decode(arr[0]);
	}

	public static JsonObject decodePayload(String accessToken) {
		String[] arr = accessToken.split("\\.", 3);
		if (arr.length < 2) {
			return null;
		}
		return decode(arr[1]);
	}

	private static JsonObject decode(String encoded) {
		try {
			byte[] decodedBytes = Base64.getUrlDecoder().decode(encoded);
			String decodedString = new String(decodedBytes);
			try (JsonReader reader = Json.createReader(new StringReader(decodedString))) {
				return reader.readObject();
			}
		} catch (Exception e) {
			return null;
		}
	}
}
