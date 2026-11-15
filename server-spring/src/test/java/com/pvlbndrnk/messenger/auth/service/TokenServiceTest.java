package com.pvlbndrnk.messenger.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.pvlbndrnk.messenger.auth.config.AuthProperties;
import com.pvlbndrnk.messenger.auth.domain.Token;
import com.pvlbndrnk.messenger.auth.repository.TokenRepository;
import com.pvlbndrnk.messenger.user.User;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Set;
import java.util.UUID;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

@ExtendWith(MockitoExtension.class)
public class TokenServiceTest {

    private static final Instant NOW = Instant.now().truncatedTo(ChronoUnit.SECONDS);
    private static final SecretKey KEY = new SecretKeySpec(
            "test-secret-that-is-at-least-32-bytes".getBytes(StandardCharsets.UTF_8),
            "HmacSHA256"
    );

    @Mock
    private TokenRepository tokenRepository;

    private User user;
    private JwtDecoder jwtDecoder;
    private TokenService tokenService;
    private AuthProperties authProperties = new AuthProperties(
            new AuthProperties.Jwt(
                    Duration.ofMinutes(15),
                    Duration.ofDays(30),
                    "dummy-base64-secret-for-unit-tests"
            )
    );

    @BeforeEach
    void setUp() {
        tokenService = new TokenService(
                Clock.fixed(NOW, ZoneOffset.UTC),
                new NimbusJwtEncoder(new ImmutableSecret<>(KEY)),
                authProperties,
                tokenRepository
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
        assertThat(jwt.getSubject()).isEqualTo(user.getId().toString());
        assertThat(jwt.getIssuedAt()).isEqualTo(NOW);
        assertThat(jwt.getExpiresAt()).isEqualTo(NOW.plus(authProperties.jwt().accessTokenTtl()));
        assertThat(jwt.getHeaders()).containsEntry("alg", "HS256");
    }

    @Test
    void refreshTokenExpiresAfterThirtyDays() {
        tokenService.createRefreshToken(user);
        Instant actualExpiresAt = captureSavedToken().getExpiresAt();
        Instant expectedExpiresAt = NOW.plus(authProperties.jwt().refreshTokenTtl());
        assertThat(actualExpiresAt).isEqualTo(expectedExpiresAt);
    }

    @Test
    void refreshTokenIsPersistedOnlyAsSha256Hash() throws NoSuchAlgorithmException {
        String rawToken = tokenService.createRefreshToken(user);
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(rawToken.getBytes(StandardCharsets.UTF_8));
        String hashedToken = HexFormat.of().formatHex(digest);
        Token capturedToken = captureSavedToken();

        assertThat(capturedToken.getTokenHash())
                .isNotEqualTo(rawToken)
                .isEqualTo(hashedToken);
        assertThat(capturedToken.getUser()).isSameAs(user);
    }

    @Test
    void refreshTokensAreUnique() {
        Set<String> tokens = new HashSet<>();
        for (int i = 0; i < 1_000; i++) {
            tokens.add(tokenService.createRefreshToken(user));
        }
        assertThat(tokens).hasSize(1_000);
    }

    private Token captureSavedToken() {
        ArgumentCaptor<Token> argumentCaptor = ArgumentCaptor.forClass(Token.class);
        verify(tokenRepository).save(argumentCaptor.capture());
        return argumentCaptor.getValue();
    }

    private User userWithId(UUID id) {
        User user = User.create("alice", "hash");
        ReflectionTestUtils.setField(user, "id", id);
        return user;
    }
}
