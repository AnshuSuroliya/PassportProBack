package com.example.passportVerify.passportVerifyBack.service;

import com.example.passportVerify.passportVerifyBack.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.core.userdetails.UserDetails;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

class JwtServiceTest {
    @InjectMocks
    private JwtService jwtService;

    @Mock
    private UserDetails userDetails;
    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }
    public static final String SECRET = "5367566B59703373367639792F423F4528482B4D6251655468576D5A71347437";

    @Test
    void testGenerateToken() {

        String userName = "testUser";


        String token = jwtService.generateToken(userName);


        assertNotNull(token);
    }

    @Test
    void testExtractUsername() {

        String userName = "testUser";
        String token = createToken(userName);


        String extractedUsername = jwtService.extractUsername(token);


        assertEquals(userName, extractedUsername);
    }

    @Test
    void testExtractExpiration() {

        String userName = "testUser";
        String token = createToken(userName);


        Date expirationDate = jwtService.extractExpiration(token);


        assertNotNull(expirationDate);
    }

    @Test
    void testExtractClaim() {

        String userName = "testUser";
        String token = createToken(userName);


        String extractedClaim = jwtService.extractClaim(token, Claims::getSubject);


        assertEquals(userName, extractedClaim);
    }

    @Test
    void testValidateToken_ValidToken() {

        String userName = "testUser";
        String token = createToken(userName);
        when(userDetails.getUsername()).thenReturn(userName);


        boolean isValid = jwtService.validateToken(token, userDetails);


        assertTrue(isValid);
    }
    @Test
    void testValidateToken_ValidTokenAndUserDetails() {

        User user = new User();
        user.setEmail("user@example.com");
        UserDetails userDetails = new UserDetailsInfo(user);


        String token = jwtService.generateToken(userDetails.getUsername());

        assertNotNull(token);
        assertTrue(jwtService.validateToken(token, userDetails));
    }
    @Test
    void testValidateToken_InvalidToken() {

        String userName = "testUser";
        String token = createToken(userName + "Invalid");
        when(userDetails.getUsername()).thenReturn(userName);


        boolean isValid = jwtService.validateToken(token, userDetails);


        assertFalse(isValid);
    }
    @Test
    void testValidateToken_InvalidUserDetails() {

        User user = new User();
        user.setEmail("user@example.com");
        UserDetails userDetails = new UserDetailsInfo(user);


        String token = jwtService.generateToken(userDetails.getUsername());


        User differentUser = new User();
        differentUser.setEmail("differentuser@example.com");
        UserDetails differentUserDetails = new UserDetailsInfo(differentUser);

        // Validate the token with different user details
        assertFalse(jwtService.validateToken(token, differentUserDetails));
    }
    @Test
    void testValidateToken_ExpiredToken() {

        String userName = "testUser";
        String token = createExpiredToken(userName);
        when(userDetails.getUsername()).thenReturn(userName);


        assertThrows(ExpiredJwtException.class, () -> jwtService.validateToken(token, userDetails));
    }

    private String createToken(String userName) {
        Map<String, Object> claims = new HashMap<>();
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userName)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 5))
                .signWith(getSignKey(), SignatureAlgorithm.HS256).compact();
    }

    private String createExpiredToken(String userName) {
        Map<String, Object> claims = new HashMap<>();
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userName)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() - 1000)) // Expired token
                .signWith(getSignKey(), SignatureAlgorithm.HS256).compact();
    }

    private Key getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}