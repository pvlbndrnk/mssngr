package com.pvlbndrnk.messenger.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.pvlbndrnk.messenger.auth.domain.Token;
import com.pvlbndrnk.messenger.auth.exception.InvalidTokenException;
import com.pvlbndrnk.messenger.auth.exception.UserAlreadyExistsException;
import com.pvlbndrnk.messenger.user.User;
import com.pvlbndrnk.messenger.user.UserRepository;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    private AuthService authService;

    @Mock private UserRepository userRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private TokenService tokenService;
    @Mock private AuthenticationManager authenticationManager;

    @BeforeEach
    void setUp() {
        authService = new AuthService(
                userRepository, passwordEncoder, tokenService, authenticationManager
        );
    }

    @Test
    void registerNormalizesUsernameAndStoresOnlyPasswordHash() {
        when(userRepository.existsByUsername("john")).thenReturn(false);
        when(passwordEncoder.encode("secret")).thenReturn("encoded-secret");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        User registered = authService.register(" John ", "secret");

        assertThat(registered.getUsername()).isEqualTo("john");
        assertThat(registered.getPasswordHash()).isEqualTo("encoded-secret");
    }

    @Test
    void registerRejectsTakenUsernameWithoutHashingPassword() {
        when(userRepository.existsByUsername("john")).thenReturn(true);

        assertThatThrownBy(() -> authService.register("John", "secret"))
                .isInstanceOf(UserAlreadyExistsException.class);

        verify(userRepository, never()).save(any());
        verifyNoInteractions(passwordEncoder);
    }

    @Test
    void registerTreatsConcurrentUniqueViolationAsTakenUsername() {
        when(userRepository.existsByUsername("john")).thenReturn(false);
        when(passwordEncoder.encode("secret")).thenReturn("encoded-secret");
        when(userRepository.save(any(User.class))).thenThrow(
                new DataIntegrityViolationException("duplicate key users_username_key")
        );

        assertThatThrownBy(() -> authService.register("John", "secret"))
                .isInstanceOf(UserAlreadyExistsException.class);
    }

    @Test
    void loginPassesRawCredentialsToAuthenticationManagerAndIssuesBothTokens() {
        User user = userWithId("John");
        when(authenticationManager.authenticate(any()))
                .thenReturn(UsernamePasswordAuthenticationToken.authenticated(
                        "John",
                        null,
                        List.of()
                ));
        when(userRepository.findByUsername("John")).thenReturn(Optional.of(user));
        when(tokenService.createAccessToken(user)).thenReturn("access-token");
        when(tokenService.createRefreshToken(user)).thenReturn("refresh-token");
        when(tokenService.accessTokenTtlInSeconds()).thenReturn(900L);

        LoginResult result = authService.login("John", "secret");

        assertThat(result).isEqualTo(new LoginResult(user, "access-token", "refresh-token", 900L));
        verify(authenticationManager).authenticate(argThat(request ->
                !request.isAuthenticated()
                        && request.getName().equals("John")
                        && "secret".equals(request.getCredentials())));
    }

    @Test
    void loginWithBadCredentialsIssuesNoTokens() {
        when(authenticationManager.authenticate(any()))
                .thenThrow(new BadCredentialsException("Bad credentials"));

        assertThatThrownBy(() -> authService.login("Jogn", "wrong"))
                .isInstanceOf(BadCredentialsException.class);

        verifyNoInteractions(tokenService);
    }

    @Test
    void refreshIssuesAccessTokenForRefreshTokenOwner() {
        User john = userWithId("John");
        Token token = Token.create(john, "hash", Instant.now().plusSeconds(20));
        when(tokenService.findValidRefreshToken("refresh-token")).thenReturn(token);
        when(tokenService.createAccessToken(john)).thenReturn("new-access-token");
        when(tokenService.accessTokenTtlInSeconds()).thenReturn(900L);

        TokenResult tokenResult = authService.createAccessToken("refresh-token");

        assertThat(tokenResult).isEqualTo(new TokenResult(john, "new-access-token", 900L));
    }

    @Test
    void refreshWithInvalidTokenIssuesNoAccessToken() {
        when(tokenService.findValidRefreshToken("invalid-token"))
                .thenThrow(new InvalidTokenException());

        assertThatThrownBy(() -> authService.createAccessToken("invalid-token"))
                .isInstanceOf(InvalidTokenException.class);

        verify(tokenService, never()).createRefreshToken(any());
    }

    private User userWithId(String username) {
        User user = User.create(username, "hash");
        ReflectionTestUtils.setField(user, "id", UUID.randomUUID());
        return user;
    }
}
