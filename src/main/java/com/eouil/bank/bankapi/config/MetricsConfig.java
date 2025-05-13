package com.eouil.bank.bankapi.config;

import io.micrometer.prometheus.PrometheusMeterRegistry;
import io.prometheus.client.CollectorRegistry;
import io.prometheus.client.exporter.PushGateway;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableScheduling
@Profile("!test")
public class MetricsConfig {
    private static final Logger logger = LoggerFactory.getLogger(MetricsConfig.class);

    private final PrometheusMeterRegistry meterRegistry;
    private final String pushGatewayHost;
    private final int pushGatewayPort;
    private final String jobName;

    public MetricsConfig(PrometheusMeterRegistry meterRegistry,
                         @Value("${custom.metrics.pushgateway.base-url}") String pushGatewayUrl,
                         @Value("${custom.metrics.pushgateway.job}") String jobName) throws MalformedURLException {
        this.meterRegistry = meterRegistry;
        this.jobName = jobName;

        // URL 파싱 로직 추가
        URL url = new URL(pushGatewayUrl);
        this.pushGatewayHost = url.getHost();
        this.pushGatewayPort = url.getPort() != -1 ? url.getPort() : url.getDefaultPort();
    }

    @Scheduled(fixedRate = 30000) // 30초마다 실행
    public void pushMetrics() {
        CollectorRegistry collectorRegistry = meterRegistry.getPrometheusRegistry();
        PushGateway pushGateway = new PushGateway(pushGatewayHost + ":" + pushGatewayPort);

        Map<String, String> groupingKey = new HashMap<>();
        groupingKey.put("instance", "my-app-instance");

        try {
            pushGateway.pushAdd(collectorRegistry, jobName, groupingKey);
            logger.info("✅ Metrics pushed to PushGateway successfully to {}:{}", pushGatewayHost, pushGatewayPort);
        } catch (IOException e) {
            logger.error("❌ Failed to push metrics to PushGateway at {}:{}", pushGatewayHost, pushGatewayPort, e);
        }
    }
}