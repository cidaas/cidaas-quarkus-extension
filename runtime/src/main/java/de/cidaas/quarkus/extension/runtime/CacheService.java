package de.cidaas.quarkus.extension.runtime;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;
import io.quarkus.scheduler.Scheduled;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import jakarta.json.JsonObject;

/**
 * Backward-compatible JWK cache facade (delegates to {@link CidaasInstanceService}).
 */
@ApplicationScoped
public class CacheService {

	@Inject
	CidaasInstanceService instanceService;

	private static final Logger LOG = LoggerFactory.getLogger(CacheService.class);

	void onStart(@Observes StartupEvent ev) {
		LOG.debug("Cidaas extension started — JWK cache loads on first use");
	}

	public JsonObject getJwks() {
		return instanceService.getJwks(instanceService.defaultBaseUrl());
	}

	@Scheduled(every = "${de.cidaas.quarkus.extension.cache-refresh-rate:86400s}")
	public void refreshJwks() {
		String baseUrl = instanceService.defaultBaseUrl();
		if (baseUrl == null || baseUrl.isBlank() || !baseUrl.contains("://")) {
			return;
		}
		instanceService.invalidateJwksCache();
		getJwks();
		LOG.info("Refreshed JWK cache");
	}

	void onStop(@Observes ShutdownEvent ev) {
		instanceService.invalidateJwksCache();
	}
}
