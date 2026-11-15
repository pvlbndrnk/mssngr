package com.pvlbndrnk.messenger.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.pvlbndrnk.messenger.auth.exception.UserAlreadyExistsException;
import com.pvlbndrnk.messenger.user.User;
import com.pvlbndrnk.messenger.user.UserRepository;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;

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
}
