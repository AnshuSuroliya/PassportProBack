package com.example.passportVerify.passportVerifyBack.exception;

import com.example.passportVerify.passportVerifyBack.response.LoginResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.*;

class UserControllerHandlerTest {
    @InjectMocks
    private UserControllerHandler userControllerHandler;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.initMocks(this);
    }
    @Test
    public void testHandleInvalidCredentialsException() {
        // Arrange
        UserException userException = new UserException("Wrong Password");

        // Act
        ResponseEntity<LoginResponse> responseEntity = userControllerHandler.handleInvalidCredentialsException();

        // Assert
        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());

        // Verify the content of the response
        LoginResponse loginResponse = responseEntity.getBody();
        assertEquals(null, loginResponse.getEmail());
        assertEquals(null, loginResponse.getJwt());
        assertEquals("Wrong Password", loginResponse.getMessage());
        assertEquals(false, loginResponse.getSuccess());
    }

}