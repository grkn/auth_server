package com.to.go.fit.security;

import lombok.ToString;
import org.springframework.security.oauth2.jwt.JwtClaimAccessor;

import java.net.URL;
import java.time.Instant;
import java.util.List;
import java.util.Map;
// Remove toString later
@ToString
public final class Data implements JwtClaimAccessor {
    private String username;
    private Map<String, Object> claims;
    private Map<String, Object> headers;
    private String tokenValue;

    public Data(String username, Map<String, Object> claims, Map<String, Object> headers, String tokenValue) {
        this.username = username;
        this.claims = claims;
        this.headers = headers;
        this.tokenValue = tokenValue;
    }

    @Override
    public Map<String, Object> getClaims() {
        return claims;
    }

    @Override
    public <T> T getClaim(String claim) {
        return (T) claims.get(claim);
    }

    @Override
    public boolean hasClaim(String claim) {
        return JwtClaimAccessor.super.hasClaim(claim);
    }

    @Override
    public String getClaimAsString(String claim) {
        return JwtClaimAccessor.super.getClaimAsString(claim);
    }

    @Override
    public Boolean getClaimAsBoolean(String claim) {
        return JwtClaimAccessor.super.getClaimAsBoolean(claim);
    }

    @Override
    public Instant getClaimAsInstant(String claim) {
        return JwtClaimAccessor.super.getClaimAsInstant(claim);
    }

    @Override
    public URL getClaimAsURL(String claim) {
        return JwtClaimAccessor.super.getClaimAsURL(claim);
    }

    @Override
    public Map<String, Object> getClaimAsMap(String claim) {
        return JwtClaimAccessor.super.getClaimAsMap(claim);
    }

    @Override
    public List<String> getClaimAsStringList(String claim) {
        return JwtClaimAccessor.super.getClaimAsStringList(claim);
    }

    @Override
    public URL getIssuer() {
        return JwtClaimAccessor.super.getIssuer();
    }

    @Override
    public String getSubject() {
        return JwtClaimAccessor.super.getSubject();
    }

    @Override
    public List<String> getAudience() {
        return JwtClaimAccessor.super.getAudience();
    }

    @Override
    public Instant getExpiresAt() {
        return JwtClaimAccessor.super.getExpiresAt();
    }

    @Override
    public Instant getNotBefore() {
        return JwtClaimAccessor.super.getNotBefore();
    }

    @Override
    public Instant getIssuedAt() {
        return JwtClaimAccessor.super.getIssuedAt();
    }

    @Override
    public String getId() {
        return JwtClaimAccessor.super.getId();
    }

    public String getUsername() {
        return username;
    }

    public Map<String, Object> getHeaders() {
        return headers;
    }

    public String getTokenValue() {
        return tokenValue;
    }
}