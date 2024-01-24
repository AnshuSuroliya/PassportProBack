//package com.example.passportVerify.passportVerifyBack.config;
//
//import static org.junit.jupiter.api.Assertions.*;
//import com.example.passportVerify.passportVerifyBack.filter.AuthEntryPointJwt;
//import com.example.passportVerify.passportVerifyBack.filter.JwtAuthFilter;
//import com.example.passportVerify.passportVerifyBack.service.UserService;
//import org.junit.jupiter.api.Test;
//import org.mockito.InjectMocks;
//import org.mockito.Mock;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.context.annotation.Import;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.test.annotation.DirtiesContext;
//import org.springframework.test.context.ContextConfiguration;
//import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
//import org.springframework.test.web.servlet.MockMvc;
//import org.springframework.test.web.servlet.setup.MockMvcBuilders;
//import org.springframework.web.cors.CorsConfiguration;
//import org.springframework.web.cors.CorsConfigurationSource;
//import org.springframework.web.filter.CorsFilter;
//
//import java.util.List;
//
//import static org.mockito.Mockito.*;
//
//@SpringJUnitConfig(classes = SecurityConfigTest.TestConfig.class)
//class SecurityConfigTest {
//    @Mock
//    private AuthEntryPointJwt unAuthorizeHandler;
//
//    @Mock
//    private UserService userDetailsService;
//
//    @Autowired
//    private JwtAuthFilter jwtAuthFilter;
//
//    @InjectMocks
//    private SecurityConfig securityConfig;
//
//    @Test
//    void testJwtAuthFilterBeanCreation() {
//        assertNotNull(jwtAuthFilter);
//    }
//
//    @Test
//    void testUserDetailsServiceBeanCreation() {
//        assertNotNull(userDetailsService);
//    }
//
//    @Test
//    void testCorsConfigurationSourceBeanCreation() {
//        CorsConfigurationSource corsConfigurationSource = securityConfig.corsConfigurationSource();
//        assertNotNull(corsConfigurationSource);
//        // Add more assertions as needed for CorsConfigurationSource
//    }
//
//    @Test
//    void testSecurityFilterChainConfiguration() throws Exception {
//        SecurityFilterChain securityFilterChain = securityConfig.securityFilterChain(mock(HttpSecurity.class));
//        assertNotNull(securityFilterChain);
//
//        // You can further test HttpSecurity configuration here
//    }
//
//    @Test
//    void testPasswordEncoderBeanCreation() {
//        PasswordEncoder passwordEncoder = securityConfig.passwordEncoder();
//        assertNotNull(passwordEncoder);
//    }
//
//    @Test
//    void testAuthenticationProviderBeanCreation() {
//        assertNotNull(securityConfig.authenticationProvider());
//    }
//
//    @Test
//    void testAuthenticationManagerBeanCreation() throws Exception {
//        AuthenticationManager authenticationManager = securityConfig.authenticationManager(mock(AuthenticationConfiguration.class));
//        assertNotNull(authenticationManager);
//    }
//
//    @Configuration
//    @Import(SecurityConfig.class)
//    static class TestConfig {
//
//        @Bean
//        public JwtAuthFilter jwtAuthFilter() {
//            return mock(JwtAuthFilter.class);
//        }
//
//        @Bean
//        public AuthEntryPointJwt unAuthorizeHandler() {
//            return mock(AuthEntryPointJwt.class);
//        }
//
//        @Bean
//        public UserService userDetailsService() {
//            return mock(UserService.class);
//        }
//
//        @Bean
//        public PasswordEncoder passwordEncoder() {
//            return mock(PasswordEncoder.class);
//        }
//
//        @Bean
//        public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
//            return config.getAuthenticationManager();
//        }
//
//        @Bean
//        public CorsConfigurationSource corsConfigurationSource() {
//            CorsConfiguration configuration = new CorsConfiguration();
//            configuration.addAllowedOriginPattern("*");
//            configuration.setAllowedMethods(List.of("*"));
//            configuration.setAllowedHeaders(List.of("*"));
//
//            org.springframework.web.cors.UrlBasedCorsConfigurationSource source = new org.springframework.web.cors.UrlBasedCorsConfigurationSource();
//            source.registerCorsConfiguration("/**", configuration);
//            return source;
//        }
//    }
//
//}