package com.pvlbndrnk.messenger.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

@Validated
@ConfigurationProperties(prefix = "auth")
public record AuthProperties(
        @Valid Jwt jwt
) {
    public record Jwt(
            @NotNull Duration accessTokenTtl,
            @NotNull Duration refreshTokenTtl,
            @NotBlank String secretBase64
    ) {}
}
