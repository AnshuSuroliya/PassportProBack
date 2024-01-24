package com.example.passportVerify.passportVerifyBack.service;

import com.example.passportVerify.passportVerifyBack.entity.User;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class UserDetailsInfoTest {
    @Test
    void testUserDetailsInfoCreation() {

        User mockUser = new User();
        mockUser.setEmail("test@example.com");
        mockUser.setPassword("password");


        UserDetailsInfo userDetailsInfo = new UserDetailsInfo(mockUser);


        assertEquals(mockUser.getEmail(), userDetailsInfo.getUsername());
        assertEquals(mockUser.getPassword(), userDetailsInfo.getPassword());
    }

    @Test
    void testGetAuthorities() {

        User mockUser = new User();
        UserDetailsInfo userDetailsInfo = new UserDetailsInfo(mockUser);


        List<GrantedAuthority> authorities = (List<GrantedAuthority>) userDetailsInfo.getAuthorities();


        assertEquals(null, authorities);
    }

    @Test
    void testIsAccountNonExpired() {

        User mockUser = new User();
        UserDetailsInfo userDetailsInfo = new UserDetailsInfo(mockUser);


        assertEquals(true, userDetailsInfo.isAccountNonExpired());
    }

    @Test
    void testIsAccountNonLocked() {

        User mockUser = new User();
        UserDetailsInfo userDetailsInfo = new UserDetailsInfo(mockUser);


        assertEquals(true, userDetailsInfo.isAccountNonLocked());
    }

    @Test
    void testIsCredentialsNonExpired() {

        User mockUser = new User();
        UserDetailsInfo userDetailsInfo = new UserDetailsInfo(mockUser);


        assertEquals(true, userDetailsInfo.isCredentialsNonExpired());
    }

    @Test
    void testIsEnabled() {

        User mockUser = new User();
        UserDetailsInfo userDetailsInfo = new UserDetailsInfo(mockUser);


        assertEquals(true, userDetailsInfo.isEnabled());
    }

}