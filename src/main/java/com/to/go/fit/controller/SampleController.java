package com.to.go.fit.controller;

import com.to.go.fit.security.JwtTokenContext;
import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/tgf")
@RequiredArgsConstructor
public class SampleController {

    private final JwtTokenContext jwtTokenContext;

    @GetMapping(value = "/data")
    @PreAuthorize(value = "hasAuthority(\"SCOPE_write\")")
    public ResponseEntity<Echo> echo() {
        return ResponseEntity.ok(Echo.builder().msg(jwtTokenContext.getJwtData().toString()).build());
    }

    @Builder
    @Getter
    private static class Echo {
        String msg;
    }
}
