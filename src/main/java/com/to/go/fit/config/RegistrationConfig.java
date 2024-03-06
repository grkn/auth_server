package com.to.go.fit.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.net.URI;
import java.util.Set;

@Configuration
public class RegistrationConfig {

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(BCryptPasswordEncoder encoder) {
        return new InMemoryRegisteredClientRepository(RegisteredClient.withId("tgf").scopes(consumer -> consumer.addAll(Set.of("read", "write")))
                .clientId("user")
                .clientSecret(encoder.encode("password"))
                .clientAuthenticationMethods(clientAuthenticationMethods -> clientAuthenticationMethods.addAll(Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC
                        , ClientAuthenticationMethod.CLIENT_SECRET_POST, ClientAuthenticationMethod.CLIENT_SECRET_JWT)))
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://localhost:9090/login/oauth2/code/tgf").build());
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(
                ClientRegistration
                        .withRegistrationId("tgf")
                        .scope("read", "write")
                        .clientId("user")
                        .clientSecret("password")
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                        .tokenUri(URI.create("http://localhost:9090/oauth2/token").toString())
                        .redirectUri("http://localhost:9090/login/oauth2/code/tgf")
                        .build());
    }
}
