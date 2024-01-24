package com.example.passportVerify.passportVerifyBack.service;

import com.example.passportVerify.passportVerifyBack.entity.User;
import com.example.passportVerify.passportVerifyBack.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

class UserServiceTest {
    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private UserService userService;
    @BeforeEach
    public void setUp() {
        MockitoAnnotations.initMocks(this);
    }
    @Test
    void testLoadUserByUsername_UserFound() {

        String userEmail = "test@example.com";
        User mockUser = new User();
        mockUser.setEmail(userEmail);
        when(userRepository.findByEmail(userEmail)).thenReturn(mockUser);


        UserDetails userDetails = userService.loadUserByUsername(userEmail);


        assertNotNull(userDetails);
        assertEquals(userEmail, userDetails.getUsername());
    }

    @Test
    void testLoadUserByUsername_UserNotFound() {

        String userEmail = "nonexistent@example.com";
        when(userRepository.findByEmail(userEmail)).thenReturn(null);


        assertThrows(NullPointerException.class, () -> userService.loadUserByUsername(userEmail));
    }

}