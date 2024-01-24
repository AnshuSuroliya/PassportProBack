package com.example.passportVerify.passportVerifyBack.controller;

import com.example.passportVerify.passportVerifyBack.entity.User;
import com.example.passportVerify.passportVerifyBack.exception.UserException;
import com.example.passportVerify.passportVerifyBack.exception.ValidationException;
import com.example.passportVerify.passportVerifyBack.repository.UserRepository;
import com.example.passportVerify.passportVerifyBack.request.GetRequest;
import com.example.passportVerify.passportVerifyBack.request.Login;
import com.example.passportVerify.passportVerifyBack.response.LoginResponse;
import com.example.passportVerify.passportVerifyBack.response.SignupResponse;
import com.example.passportVerify.passportVerifyBack.service.UserRegisterServiceImple;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class UserControllerTest {

    @Mock
    UserRegisterServiceImple userRegisterService;

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private UserController userController;
    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testRegister_Success() throws UserException, ValidationException {

        User user = new User();
        SignupResponse signupResponse=new SignupResponse("User Registered Successfully",true);
        when(userRegisterService.signUp(any(User.class))).thenReturn(new ResponseEntity<>(signupResponse, HttpStatus.CREATED).getBody());
        //Mockito.when(userRepository.findByEmail(any())).thenReturn(null);




        ResponseEntity<SignupResponse> responseEntity = userController.register(user);


        assertEquals(HttpStatus.CREATED, responseEntity.getStatusCode());
        assertEquals("User Registered Successfully", responseEntity.getBody().getMessage());
    }

    @Test
    void testLogin_Success() throws UserException, ValidationException {

        Login login = new Login();
        when(userRegisterService.signIn(login)).thenReturn(new LoginResponse(true, "jwtToken", "Login Successful","test@gmail.com"));


        ResponseEntity<LoginResponse> responseEntity = userController.login(login);


        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
        assertEquals(true, responseEntity.getBody().getSuccess());
        assertEquals("jwtToken", responseEntity.getBody().getJwt());
        assertEquals("Login Successful", responseEntity.getBody().getMessage());
        verify(userRegisterService, times(1)).signIn(login);
    }

    @Test
    void testGetUser_Success() throws UserException {

        GetRequest getRequest = new GetRequest();
        User user=new User();
        when(userRegisterService.getUser(getRequest)).thenReturn(user);


        ResponseEntity<?> responseEntity = userController.getUser(getRequest);


        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
        assertEquals(user, responseEntity.getBody());
        verify(userRegisterService, times(1)).getUser(getRequest);
    }
    @Test
    void testRegister_Failure() throws UserException, ValidationException {

        User user = new User();
        when(userRegisterService.signUp(user)).thenThrow(new ValidationException("Invalid user"));


        ValidationException exception = assertThrows(ValidationException.class, () -> {
            userController.register(user);
        });

        assertEquals("Invalid user", exception.getMessage());
        verify(userRegisterService, times(1)).signUp(user);
    }

    @Test
    void testLogin_Failure() throws UserException, ValidationException {

        Login login = new Login();
        when(userRegisterService.signIn(login)).thenThrow(new UserException("Invalid login"));


        UserException exception = assertThrows(UserException.class, () -> {
            userController.login(login);
        });

        assertEquals("Invalid login", exception.getMessage());
        verify(userRegisterService, times(1)).signIn(login);
    }

    @Test
    void testGetUser_Failure() throws UserException {

        GetRequest getRequest = new GetRequest();
        when(userRegisterService.getUser(getRequest)).thenThrow(new UserException("User not found"));


        UserException exception = assertThrows(UserException.class, () -> {
            userController.getUser(getRequest);
        });

        assertEquals("User not found", exception.getMessage());
        verify(userRegisterService, times(1)).getUser(getRequest);
    }

}