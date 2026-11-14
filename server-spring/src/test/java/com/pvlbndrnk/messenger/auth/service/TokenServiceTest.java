package com.pvlbndrnk.messenger.auth.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.pvlbndrnk.messenger.auth.repository.TokenRepository;
import com.pvlbndrnk.messenger.user.User;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class TokenServiceTest {

    private static final Duration ACCESS_TTL = Duration.ofMinutes(15);
    private static final SecretKey KEY = new SecretKeySpec(
            "test-secret-that-is-at-least-32-bytes".getBytes(StandardCharsets.UTF_8),
            "HmacSHA256"
    );

    private User user;
    private JwtDecoder jwtDecoder;
    private TokenService tokenService;
    private TokenRepository tokenRepository;

    @BeforeEach
    void setUp() {
        tokenService = new TokenService(
                new NimbusJwtEncoder(new ImmutableSecret<>(KEY)),
                tokenRepository,
                ACCESS_TTL
        );
        jwtDecoder = NimbusJwtDecoder
                .withSecretKey(KEY)
                .macAlgorithm(MacAlgorithm.HS256)
                .build();
        user = userWithId(UUID.randomUUID());
    }

    @Test
    void accessTokenCarriesUserIdAsSubjectAndExpiresAfterTtl() {
        String accessToken = tokenService.createAccessToken(user);
        Jwt jwt = jwtDecoder.decode(accessToken);
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        assertThat(jwt.getSubject()).isEqualTo(user.getId().toString());
        assertThat(jwt.getIssuedAt()).isEqualTo(now);
        assertThat(jwt.getExpiresAt()).isEqualTo(now.plus(ACCESS_TTL));
        assertThat(jwt.getHeaders()).containsEntry("alg", "HS256");
    }

    private User userWithId(UUID id) {
        User user = User.create("alice", "hash");
        ReflectionTestUtils.setField(user, "id", id);
        return user;
    }
}
