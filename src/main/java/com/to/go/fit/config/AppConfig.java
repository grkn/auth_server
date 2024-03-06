package com.to.go.fit.config;

import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.web.socket.config.annotation.EnableWebSocket;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.List;

@EnableWebSocket
@EnableCaching
@EnableAsync
@Configuration
public class AppConfig {

    public byte[] generateKey() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[256];
        random.nextBytes(bytes);
        return bytes;
    }

    @Bean
    public SecretKey initializeKey() {
        return new SecretKeySpec(generateKey(), "HmacSHA512");
    }

    @Bean
    @Primary
    public JwtDecoder decoder(SecretKey key) {
        DefaultJWTProcessor defaultJWTProcessor = new DefaultJWTProcessor();
        defaultJWTProcessor.setJWSKeySelector((header, context) -> List.of(key));
        return new NimbusJwtDecoder(defaultJWTProcessor);
    }

}
