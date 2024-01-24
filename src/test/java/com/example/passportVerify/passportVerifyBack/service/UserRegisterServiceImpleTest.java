package com.example.passportVerify.passportVerifyBack.service;

import com.example.passportVerify.passportVerifyBack.entity.User;
import com.example.passportVerify.passportVerifyBack.exception.UserException;
import com.example.passportVerify.passportVerifyBack.exception.ValidationException;
import com.example.passportVerify.passportVerifyBack.repository.UserRepository;
import com.example.passportVerify.passportVerifyBack.request.GetRequest;
import com.example.passportVerify.passportVerifyBack.request.Login;
import com.example.passportVerify.passportVerifyBack.response.LoginResponse;
import com.example.passportVerify.passportVerifyBack.response.SignupResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class UserRegisterServiceImpleTest {

        @Mock
        private UserRepository userRepository;

        @Mock
        private AuthenticationManager authenticationManager;

        @Mock
        private JwtService jwtService;

        @Mock
        private ValidationService validationService;

        @InjectMocks
        private UserRegisterServiceImple userRegisterServiceImple;
        @Mock
        private UserService userService;
        @BeforeEach
        public void setUp() {
            MockitoAnnotations.initMocks(this);
        }

        @Test
        public void testSignUp_Success() throws UserException, ValidationException {
            User user = new User();
            user.setFirstName("Pankaj");
            user.setLastName("Sharma");
            user.setPhoneNumber("9876578900");
            user.setEmail("pankaj@gmail.com");
            BCryptPasswordEncoder bCryptPasswordEncoder=new BCryptPasswordEncoder();
            user.setPassword(bCryptPasswordEncoder.encode("pankaj@123"));
            when(validationService.nameValidation(any())).thenReturn(true);
            when(validationService.phoneNumberValidation(any())).thenReturn(true);
            when(validationService.emailValidation(any())).thenReturn(true);
            when(userRepository.findByEmail(any())).thenReturn(null);
            when(userRepository.save(any())).thenReturn(user);

            SignupResponse response = userRegisterServiceImple.signUp(user);

            assertEquals("User Registered Successfully", response.getMessage());

        }

        @Test
        public void testSignUp_UserAlreadyPresent() throws UserException, ValidationException {
            User user = new User();
            user.setFirstName("Pankaj");
            user.setLastName("Sharma");
            user.setPhoneNumber("9876578900");
            user.setEmail("pankaj@gmail.com");
            BCryptPasswordEncoder bCryptPasswordEncoder=new BCryptPasswordEncoder();
            user.setPassword(bCryptPasswordEncoder.encode("pankaj@123)"));
            when(validationService.nameValidation(any())).thenReturn(true);
            when(validationService.phoneNumberValidation(any())).thenReturn(true);
            when(validationService.emailValidation(any())).thenReturn(true);

            when(userRepository.findByEmail(any())).thenReturn(user);

            SignupResponse response = userRegisterServiceImple.signUp(user);

            assertEquals("User Already Present", response.getMessage());

        }
        @Test
        public void Signup_Exception() throws ValidationException {
            User user=new User();
            user.setFirstName("Pankaj");
            user.setLastName("Sharma");
            user.setPhoneNumber("9876578900");
            user.setEmail("pankaj@gmail.com");
            when(validationService.nameValidation(any())).thenReturn(true);
            when(validationService.phoneNumberValidation(any())).thenReturn(true);
            when(validationService.emailValidation(any())).thenReturn(true);
            when(userRepository.findByEmail("nonexistent@example.com")).thenReturn(null);

            // Set the userRepository in your service using reflection or constructor injection


            Exception exception = assertThrows(UserException.class, () -> userRegisterServiceImple.signUp(user));


            assertEquals("Error in creating account", exception.getMessage());

        }

        @Test
        public void testSignUp_ValidationFailure() throws UserException, ValidationException {
            User user = new User();
            user.setId(user.getId());
            user.setFirstName("Pan5637");
            user.setLastName("Sha43rma");
            user.setPhoneNumber("98765789fdh");
            user.setEmail("pankaj@gmail.com");
            SignupResponse signupResponse=new SignupResponse();
            signupResponse.setMessage(null);
            SignupResponse signupResponse1=new SignupResponse(null,false);
            BCryptPasswordEncoder bCryptPasswordEncoder=new BCryptPasswordEncoder();
            user.setPassword(bCryptPasswordEncoder.encode("pankaj@123"));
            when(validationService.nameValidation(any())).thenReturn(false);
            when(validationService.phoneNumberValidation(any())).thenReturn(false);
            when(validationService.emailValidation(any())).thenReturn(false);

            assertThrows(ValidationException.class, () -> userRegisterServiceImple.signUp(user));

        }

        @Test
        public void testSignIn_Success() throws UserException, ValidationException {
            Login login = new Login("test@example.com", "password");
            User user = new User();
            user.setEmail("test@example.com");
            user.setPassword(new BCryptPasswordEncoder().encode("password"));

            when(validationService.emailValidation(any())).thenReturn(true);
            when(userRepository.findByEmail(login.getEmail())).thenReturn(user);

            Authentication authentication = mock(Authentication.class);
            when(authentication.isAuthenticated()).thenReturn(true);
            when(authenticationManager.authenticate(any())).thenReturn(authentication);

            when(jwtService.generateToken(login.getEmail())).thenReturn("fakeToken");

            // Act
            LoginResponse loginResponse = userRegisterServiceImple.signIn(login);

            // Assert
            assertNotNull(loginResponse);
            assertTrue(loginResponse.getSuccess());
            assertEquals("fakeToken", loginResponse.getJwt());
            assertEquals("Login Successfull!", loginResponse.getMessage());
            assertEquals("test@example.com", loginResponse.getEmail());
            verify(validationService, times(1)).emailValidation(login.getEmail());
            verify(userRepository, times(1)).findByEmail(login.getEmail());
            verify(authenticationManager, times(1)).authenticate(any());
            verify(jwtService, times(1)).generateToken(login.getEmail());

//		User user = new User();
//		user.setFirstName("Pankaj");
//		user.setLastName("Sharma");
//		user.setPhoneNumber("9876578900");
//		user.setEmail("pankaj@gmail.com");
//		BCryptPasswordEncoder bCryptPasswordEncoder=new BCryptPasswordEncoder();
//		user.setPassword(bCryptPasswordEncoder.encode("pankaj@123"));
//            when(validationService.signinValidation(any(Login.class))).thenReturn(true);
//            when(userRepository.findByEmail(any())).thenReturn(new User());
//            Mockito.when(authenticationManager.authenticate(any())).thenReturn(Mockito.mock(Authentication.class));
//            when(jwtService.generateToken(any())).thenReturn("fakeToken");
//            Login login=new Login();
//            login.setEmail("pankaj@gmail.com");
//            login.setPassword("pankaj@123");
//            LoginResponse response = userRegisterServiceImple.signIn(login);
//
//            assertEquals("Login Successfull!", response.getSuccess());

        }

        @Test
        public void testSignIn_WrongEmail() throws UserException, ValidationException {
            Login login = new Login();
            login.setEmail("pan@gmail.com");
            login.setPassword("pankaj@123");// create a login object with necessary data
            when(validationService.emailValidation(any())).thenReturn(true);
            when(userRepository.findByEmail(any())).thenReturn(null);

            LoginResponse response = userRegisterServiceImple.signIn(login);

            assertEquals(false, response.getSuccess());
            assertEquals("Wrong Email", response.getMessage());

        }

        @Test
        public void testSignIn_WrongPassword() throws UserException, ValidationException {
            Login login = new Login();
            login.setEmail("pankaj@gmail.com");
            login.setPassword("pan23");// create a login object with necessary data
            when(validationService.emailValidation(any())).thenReturn(true);
            when(userRepository.findByEmail(any())).thenReturn(new User());
            when(authenticationManager.authenticate(any())).thenReturn(mock(Authentication.class));

            LoginResponse response = userRegisterServiceImple.signIn(login);

            assertEquals(false, response.getSuccess());
            assertEquals("Wrong Password", response.getMessage());

        }

        @Test
        public void testSignIn_ValidationFailure() throws UserException, ValidationException {
            Login login = new Login();
            login.setEmail("pan.gmail.com");
            login.setPassword("pank123");//
            LoginResponse loginResponse=new LoginResponse();
            loginResponse.setSuccess(false);
            loginResponse.setMessage(null);
            loginResponse.setJwt(null);
            loginResponse.setEmail(null);
            loginResponse.getEmail();
            LoginResponse loginResponse1=new LoginResponse(false,null,null,null);
            when(validationService.emailValidation(any())).thenReturn(false);

            assertThrows(ValidationException.class, () -> userRegisterServiceImple.signIn(login));

        }
        @Test
        void testUserExceptionMessage() {

            String errorMessage = "This is an error message.";


            UserException userException=new UserException(errorMessage);


            assertEquals(errorMessage, userException.getMessage());
        }

        @Test
        void testUserExceptionWithNullMessage() {

            UserException userException=new UserException(null);


            assertEquals(null, userException.getMessage());
        }


    @Test
    public void testSignInWithUserException() throws ValidationException {


        Login login = new Login("nonexistent@example.com", "some_password");

        AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
        when(userRepository.findByEmail(any())).thenReturn(new User());
        when(validationService.emailValidation(any())).thenReturn(true);
        when(authenticationManager.authenticate(any())).thenReturn(mock(org.springframework.security.core.Authentication.class));

        // Set the authenticationManager in your service using reflection or constructor injection


        Exception exception = assertThrows(UserException.class, () -> userRegisterServiceImple.signIn(login));


        assertEquals("error in login", exception.getMessage());
    }
    @Test
    public void testGetUserNotFound() {


        GetRequest getRequest = new GetRequest();
        getRequest.setEmail("nonexistent@example.com");

        UserRepository userRepository = mock(UserRepository.class);

        when(userRepository.findByEmail("nonexistent@example.com")).thenReturn(null);

        // Set the userRepository in your service using reflection or constructor injection


        Exception exception = assertThrows(UserException.class, () -> userRegisterServiceImple.getUser(getRequest));


        assertEquals("Error fetching user", exception.getMessage());
    }
    @Test
    void testGetUser_Successful() throws UserException {
        // Arrange
        GetRequest getRequest = new GetRequest("user@example.com");
        User user = new User();
        user.setEmail("user@example.com");


        when(userRepository.findByEmail(getRequest.getEmail())).thenReturn(user);


        User result = userRegisterServiceImple.getUser(getRequest);


        assertNotNull(result);
        assertEquals("user@example.com", result.getEmail());


        verify(userRepository, times(1)).findByEmail(getRequest.getEmail());
    }

}