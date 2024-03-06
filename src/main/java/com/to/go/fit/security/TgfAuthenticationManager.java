package com.to.go.fit.security;

import com.nimbusds.jose.KeyLengthException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Set;

@Component
@RequiredArgsConstructor
public class TgfAuthenticationManager implements AuthenticationManager {

    private final JwtTokenContext jwtTokenContext;
    private final JwtDecoder jwtDecoder;
    private final RegisteredClientRepository registeredClientRepository;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (authentication instanceof OAuth2ClientAuthenticationToken token && SecurityContextHolder.getContext().getAuthentication() != null) {
            if (validateUserCredentials(token)) {
                return new OAuth2ClientAuthenticationToken(createRegisteredClient(), ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                        token.getCredentials());
            }
        } else if (authentication instanceof UsernamePasswordAuthenticationToken) {
            // Login username password flow
            if (validateUserCredentials(authentication)) {
                return new UsernamePasswordAuthenticationToken("user", "password", createDefaultAuthority("USER"));
            }
        } else if (authentication instanceof OAuth2ClientCredentialsAuthenticationToken oAuth2ClientCredentialsAuthenticationToken && SecurityContextHolder.getContext().getAuthentication() != null) {
            // Client credential flow

            OAuth2ClientAuthenticationToken oAuth2ClientAuthenticationToken = (OAuth2ClientAuthenticationToken) oAuth2ClientCredentialsAuthenticationToken.getPrincipal();
            if (validateUserCredentials(oAuth2ClientAuthenticationToken)) {
                TimeoutInformation timeoutInformation = timeoutData();
                try {

                    return new OAuth2AccessTokenAuthenticationToken(createRegisteredClient(), jwtTokenContext
                            , createAccessToken(jwtTokenContext.accessToken(), timeoutInformation.issuedAt(), timeoutInformation.expireAccessToken())
                            , createRefreshToken(timeoutInformation.issuedAt(), timeoutInformation.expireRefreshToken()));
                } catch (KeyLengthException e) {
                    throw new RuntimeException(e);
                }
            }
        } else if (authentication instanceof BearerTokenAuthenticationToken bearerTokenAuthenticationToken) {
            // Bearer token request and authentication flow

            TimeoutInformation timeoutInformation = timeoutData();
            Jwt jwt = jwtDecoder.decode(bearerTokenAuthenticationToken.getToken());
            jwtTokenContext.convert(jwt);
            return new BearerTokenAuthentication(
                    new DefaultOAuth2AuthenticatedPrincipal(
                            jwtTokenContext.getJwtData().getSubject(),
                            jwtTokenContext.getJwtData().getClaims(),
                            createDefaultAuthority("SCOPE_write"))
                    , createAccessToken(jwtTokenContext.getJwtData().getTokenValue(), timeoutInformation.issuedAt(), timeoutInformation.expireAccessToken())
                    , createDefaultAuthority("SCOPE_write"));

        } else if (authentication instanceof OAuth2RefreshTokenAuthenticationToken refreshTokenAuthenticationToken) {
            // Refresh token request and authentication flow

            TimeoutInformation timeoutInformation = timeoutData();
            if (isValidRefreshToken(refreshTokenAuthenticationToken.getRefreshToken())) {
                try {
                    return new OAuth2AccessTokenAuthenticationToken(createRegisteredClient(), jwtTokenContext,
                            createAccessToken(jwtTokenContext.accessToken(), timeoutInformation.issuedAt(), timeoutInformation.expireAccessToken())
                            , createRefreshToken(timeoutInformation.issuedAt(), timeoutInformation.expireAccessToken()));
                } catch (KeyLengthException e) {
                    throw new RuntimeException(e);
                }
            } else {
                throw new BadCredentialsException("Refresh token is invalid");
            }


        }

        throw new BadCredentialsException("Username of password wrong");
    }

    private static Set<GrantedAuthority> createDefaultAuthority(String authority) {
        return Collections.singleton(new SimpleGrantedAuthority(authority));
    }

    private static TimeoutInformation timeoutData() {
        Instant issuedAt = Instant.now();
        Instant expireAccessToken = issuedAt.plus(1, ChronoUnit.HOURS);
        Instant expireRefreshToken = issuedAt.plus(48, ChronoUnit.HOURS);
        return new TimeoutInformation(issuedAt, expireAccessToken, expireRefreshToken);
    }

    private record TimeoutInformation(Instant issuedAt, Instant expireAccessToken, Instant expireRefreshToken) {
    }

    private static boolean validateUserCredentials(Authentication token) {
        return token.getPrincipal().equals("user") && token.getCredentials().equals("password");
    }

    private OAuth2RefreshToken createRefreshToken(Instant issuedAt, Instant expireRefreshToken) throws KeyLengthException {
        return new OAuth2RefreshToken(jwtTokenContext.refreshToken(), issuedAt, expireRefreshToken);
    }

    private OAuth2AccessToken createAccessToken(String token, Instant issuedAt, Instant expireAccessToken) {
        return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, token, issuedAt, expireAccessToken);
    }

    private RegisteredClient createRegisteredClient() {
        // Fetch from database or anywhere
        return registeredClientRepository.findByClientId("user");
    }

    private boolean isValidRefreshToken(String refreshToken) {
        // validate refreshToken
        return true;
    }
}
