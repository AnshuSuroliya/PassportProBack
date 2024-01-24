//package com.example.passportVerify.passportVerifyBack.filter;
//
//import com.fasterxml.jackson.databind.ObjectMapper;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletResponse;
//import org.junit.jupiter.api.Test;
//import org.mockito.ArgumentCaptor;
//import org.mockito.Mockito;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.MediaType;
//import org.springframework.mock.web.MockHttpServletRequest;
//import org.springframework.mock.web.MockHttpServletResponse;
//import org.springframework.security.core.AuthenticationException;
//
//import java.io.IOException;
//import java.lang.reflect.Field;
//import java.util.Map;
//
//import static org.junit.jupiter.api.Assertions.assertEquals;
//import static org.mockito.Mockito.*;
//
//
//class AuthEntryPointJwtTest {
//    @Test
//    public void testCommence() throws IOException, ServletException, NoSuchFieldException, IllegalAccessException {
//
//        AuthEntryPointJwt authEntryPointJwt = new AuthEntryPointJwt();
//        Logger loggerMock = Mockito.mock(Logger.class);
//        Field loggerField = AuthEntryPointJwt.class.getDeclaredField("logger");
//        loggerField.setAccessible(true);
//        loggerField.set(authEntryPointJwt, loggerMock);
//
//        MockHttpServletRequest request = new MockHttpServletRequest();
//        MockHttpServletResponse response = new MockHttpServletResponse();
//        AuthenticationException authException = new AuthenticationException("Unauthorized") {};
//
//        // Act
//        authEntryPointJwt.commence(request, response, authException);
//
//        // Assert
//        assertEquals(HttpStatus.UNAUTHORIZED.value(), response.getStatus(), "Response status should be UNAUTHORIZED");
//
//        ObjectMapper objectMapper = new ObjectMapper();
//        ArgumentCaptor<Map<String, Object>> bodyCaptor = ArgumentCaptor.forClass(Map.class);
//        verify(loggerMock).error(eq("Unauthorize error:{}"), anyString());
//        verify(loggerMock).error("Unauthorize error:Unauthorized");
//
//        verify(response).setContentType(MediaType.APPLICATION_JSON_VALUE);
//
//        verify(response).getOutputStream();
//        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//
//        verify(loggerMock).error("Unauthorize error:{}", authException.getMessage());
//
//        verify(loggerMock).error("Unauthorize error:Unauthorized");
//
//        verify(response.getOutputStream()).write(bodyCaptor.capture().size());
//        Map<String, Object> responseBody = bodyCaptor.getValue();
//        assertEquals(HttpStatus.UNAUTHORIZED.value(), responseBody.get("status"), "Response body status should be UNAUTHORIZED");
//        assertEquals("Unauthorize", responseBody.get("error"), "Response body error should be 'Unauthorize'");
//        assertEquals("Wrong Password", responseBody.get("message"), "Response body message should be 'Wrong Password'");
//        assertEquals(request.getServletPath(), responseBody.get("path"), "Response body path should be the servlet path");
//    }
//
//}