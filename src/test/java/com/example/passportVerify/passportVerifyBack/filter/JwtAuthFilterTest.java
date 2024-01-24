//package com.example.passportVerify.passportVerifyBack.filter;
//
//import static org.junit.jupiter.api.Assertions.*;
//
//import com.example.passportVerify.passportVerifyBack.entity.User;
//import com.example.passportVerify.passportVerifyBack.service.JwtService;
//import com.example.passportVerify.passportVerifyBack.service.UserDetailsInfo;
//import com.example.passportVerify.passportVerifyBack.service.UserService;
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.junit.jupiter.api.BeforeEach;
//import org.junit.jupiter.api.Test;
//import org.junit.jupiter.api.extension.ExtendWith;
//import org.mockito.InjectMocks;
//import org.mockito.Mock;
//import org.mockito.Mockito;
//import org.mockito.MockitoAnnotations;
//import org.mockito.junit.jupiter.MockitoExtension;
//import org.springframework.mock.web.MockFilterChain;
//import org.springframework.mock.web.MockHttpServletRequest;
//import org.springframework.mock.web.MockHttpServletResponse;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UsernameNotFoundException;
//import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.context.SecurityContextHolder;
//
//import java.io.IOException;
//import java.util.Collections;
//
//import static org.junit.jupiter.api.Assertions.*;
//import static org.mockito.Mockito.*;
//@ExtendWith(MockitoExtension.class)
//class JwtAuthFilterTest {
//    @Mock
//    JwtService jwtService;
//
//    @Mock
//    private UserService userDetailsService;
//
//
//
//    @InjectMocks
//    private JwtAuthFilter jwtAuthFilter;
//
//    @Mock
//    private HttpServletRequest request;
//
//    @Mock
//    private HttpServletResponse response;
//
//    @Mock
//    private FilterChain filterChain;
//
//    @BeforeEach
//    void setUp() {
//        MockitoAnnotations.openMocks(this);
//    }
//
//    @Test
//    void testDoFilterInternalValidToken() throws ServletException, IOException {
//        // Mocking a valid JWT token
//        String validToken = "validToken";
//        UserDetailsInfo userDetails = new UserDetailsInfo(new User());
//        when(request.getHeader("Authorization")).thenReturn("Bearer " + validToken);
//        when(jwtService.validateToken(validToken,userDetails)).thenReturn(true);
//        when(jwtService.extractUsername(validToken)).thenReturn("testuser");
//
//
//        when(userDetailsService.loadUserByUsername("testuser")).thenReturn(userDetails);
//
//        jwtAuthFilter.doFilterInternal(request, response, filterChain);
//
//        verify(filterChain).doFilter(request, response);
//        verify(jwtService).extractUsername(validToken);
//        verify(jwtService).validateToken(validToken,userDetails);
//        verify(userDetailsService).loadUserByUsername("testuser");
//    }
//
//    @Test
//    void testDoFilterInternalInvalidToken() throws ServletException, IOException {
//        // Mocking an invalid JWT token
//        String invalidToken = "invalidToken";
//        UserDetailsInfo userDetails = new UserDetailsInfo(new User());
//        when(request.getHeader("Authorization")).thenReturn("Bearer " + invalidToken);
//        when(jwtService.validateToken(invalidToken,userDetails)).thenReturn(false);
//
//        jwtAuthFilter.doFilterInternal(request, response, filterChain);
//
//        verify(filterChain).doFilter(request, response);
//        verify(jwtService).validateToken(invalidToken,userDetails);
//        verify(jwtService, never()).extractUsername(any());
//        verify(userDetailsService, never()).loadUserByUsername(any());
//    }
//
//    @Test
//    void testDoFilterInternalNoToken() throws ServletException, IOException {
//        // No token provided in the request
//        when(request.getHeader("Authorization")).thenReturn(null);
//        jwtAuthFilter.doFilterInternal(request, response, filterChain);
//        UserDetailsInfo userDetails = new UserDetailsInfo(new User());
//        verify(filterChain).doFilter(request, response);
//        verify(jwtService, never()).validateToken(any(),any());
//        verify(jwtService, never()).extractUsername(any());
//        verify(userDetailsService, never()).loadUserByUsername(any());
//    }
//
//    @Test
//    void testDoFilterInternalException() throws ServletException, IOException {
//        // Mocking an exception during token processing
//        UserDetailsInfo userDetails = new UserDetailsInfo(new User());
//        when(request.getHeader("Authorization")).thenReturn("Bearer validToken");
//        when(jwtService.validateToken("validToken",userDetails)).thenThrow(new RuntimeException("Test exception"));
//
//        jwtAuthFilter.doFilterInternal(request, response, filterChain);
//
//        verify(filterChain).doFilter(request, response);
//        verify(jwtService).validateToken("validToken",userDetails);
//        verify(jwtService, never()).extractUsername(any());
//        verify(userDetailsService, never()).loadUserByUsername(any());
//    }
//
//    @Test
//    void testParseJwt() {
//        // Valid token in the Authorization header
//        when(request.getHeader("Authorization")).thenReturn("Bearer validToken");
//        String result = jwtAuthFilter.parseJwt(request);
//        assertEquals("validToken", result);
//
//        // No token in the Authorization header
//        when(request.getHeader("Authorization")).thenReturn(null);
//        result = jwtAuthFilter.parseJwt(request);
//        assertNull(result);
//
//        // Invalid token format in the Authorization header
//        when(request.getHeader("Authorization")).thenReturn("InvalidToken");
//        result = jwtAuthFilter.parseJwt(request);
//        assertNull(result);
//    }
//
//
//}