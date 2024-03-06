package com.to.go.fit.security;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.UUID;

@Component
public class JwtTokenContext extends AbstractAuthenticationToken implements Converter<Jwt, JwtTokenContext> {

    private final SecretKey secretKey;

    private final ThreadLocal<Data> threadLocal = new ThreadLocal<>();

    public String refreshToken() throws KeyLengthException {
        return accessToken();
    }

    public String accessToken() throws KeyLengthException {
        final JWSSigner jwsSigner = new MACSigner(secretKey.getEncoded());
        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.HS512)
                .x509CertSHA256Thumbprint(Base64URL.from("http://localhost:9090")).build();
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder().subject("user").jwtID(UUID.randomUUID().toString()).build();
        try {

            JWSObject jwsObject = new JWSObject(jwsHeader, jwtClaimsSet.toPayload());
            jwsObject.sign(jwsSigner);
            return jwsObject.serialize();
        } catch (KeyLengthException e) {
            throw new RuntimeException(e);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }

    }

    public JwtTokenContext(SecretKey secretKey) throws KeyLengthException {
        super(null);
        this.secretKey = secretKey;
    }

    @Override
    public Object getCredentials() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            return authentication.getCredentials();
        }
        return null;
    }

    @Override
    public Object getPrincipal() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            return authentication.getPrincipal();
        }
        return null;
    }

    @Override
    public JwtTokenContext convert(Jwt source) {
        Data data = new Data(source.getSubject(), source.getClaims(), source.getHeaders(), source.getTokenValue());
        threadLocal.set(data);
        return this;
    }

    public Data getJwtData() {
        return threadLocal.get();
    }
}
