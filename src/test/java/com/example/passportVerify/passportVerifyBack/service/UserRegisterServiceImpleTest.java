package com.example.passportVerify.passportVerifyBack.service;

import com.example.passportVerify.passportVerifyBack.entity.LoginAttempt;
import com.example.passportVerify.passportVerifyBack.entity.User;
import com.example.passportVerify.passportVerifyBack.exception.UserException;
import com.example.passportVerify.passportVerifyBack.exception.ValidationException;
import com.example.passportVerify.passportVerifyBack.repository.LoginAttemptRepository;
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

import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class UserRegisterServiceImpleTest {

        @Mock
        private UserRepository userRepository;
        @Mock
        private LoginAttemptRepository loginAttemptRepository;
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
            assertEquals(false,response.getSuccess());

        }
        @Test
        public void Signup_Exception() throws ValidationException, UserException {
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



            SignupResponse signupResponse=userRegisterServiceImple.signUp(user);
            assertEquals("Some error occured in creating account",signupResponse.getMessage());
            assertEquals(false,signupResponse.getSuccess());

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

            SignupResponse signupResponse2=userRegisterServiceImple.signUp(user);
            assertEquals("Provided input syntax is incorrect",signupResponse2.getMessage());

        }

        @Test
        public void testSignIn_Success() throws UserException, ValidationException {
            Login login = new Login("test@example.com", "password");
            User user = new User();
            user.setEmail("test@example.com");

            user.setPassword(new BCryptPasswordEncoder().encode("password"));

            when(validationService.emailValidation(any())).thenReturn(true);
            when(userRepository.findByEmail(login.getEmail())).thenReturn(user);
            when(loginAttemptRepository.findByUserId(any())).thenReturn(null);
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
            login.setPassword("pan23");
            User user=new User();
            user.setFailedTime(user.getFailedTime());
            LoginAttempt loginAttempt=new LoginAttempt();
            loginAttempt.setId(loginAttempt.getId());
            loginAttempt.setFailedAttempt(loginAttempt.getFailedAttempt());
            loginAttempt.setTime(loginAttempt.getTime());
            loginAttempt.setUser(loginAttempt.getUser());
            // create a login object with necessary data
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

            LoginResponse loginResponse2=userRegisterServiceImple.signIn(login);
            assertEquals("Provided input syntax is incorrect",loginResponse2.getMessage());

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
    public void testSignInWithUserException() throws ValidationException, UserException {


        Login login = new Login("nonexistent@example.com", "some_password");

        AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
        when(userRepository.findByEmail(any())).thenReturn(new User());
        when(validationService.emailValidation(any())).thenReturn(true);
        when(authenticationManager.authenticate(any())).thenReturn(mock(org.springframework.security.core.Authentication.class));

        // Set the authenticationManager in your service using reflection or constructor injection


       LoginResponse loginResponse=userRegisterServiceImple.signIn(login);


        assertEquals("Wrong Password,Only 2 attempts left",loginResponse.getMessage());
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
//    @Test
//    void testSignIn_UserLocked() throws UserException, ValidationException {
//        // Arrange
//        Login login = new Login();
//        login.setEmail("test@example.com");
//        login.setPassword("password");
//
//        User user = new User();
//        user.setEmail("test@example.com");
//        user.setPassword("encodedPassword");
//        user.setLocked(true);
//        user.setFailedTime(new Date(System.currentTimeMillis() - 300_000));
//        when(validationService.emailValidation(any())).thenReturn(true);
//        when(userRepository.save(user)).thenReturn(user);
//        when(userRepository.findByEmail(any())).thenReturn(user);
//
//        // Act
//        LoginResponse response = userRegisterServiceImple.signIn(login);
//
//        // Assert
//        assertNotNull(response);
//        assertFalse(response.getSuccess());
//        assertEquals("Your account is Locked!Try after 5 min.", response.getMessage());
//    }

    @Test
    void testSignIn_InvalidAttempts_OneAttemptLeft() throws UserException, ValidationException {
        // Arrange
        Login login = new Login();
        login.setEmail("test@example.com");
        login.setPassword("wrongPassword");

        User user = new User();
        user.setEmail("test@example.com");
        user.setPassword("encodedPassword");
        user.setLocked(false);
        user.setFailedTime(new Date(System.currentTimeMillis() - 60_000)); // Within continuous attempt duration

        LoginAttempt loginAttempt = new LoginAttempt();
        loginAttempt.setFailedAttempt(1);
        loginAttempt.setTime(new Date(System.currentTimeMillis() - 30_000)); // Within continuous attempt duration

        when(validationService.emailValidation(any())).thenReturn(true);
        when(userRepository.findByEmail(any())).thenReturn(user);
        when(loginAttemptRepository.findByUserId(any())).thenReturn(loginAttempt);

        // Act
        LoginResponse response = userRegisterServiceImple.signIn(login);

        // Assert
        assertNotNull(response);
        assertFalse(response.getSuccess());
        assertEquals("Wrong Password,Only 1 attempt left", response.getMessage());
    }

    @Test
    void testSignIn_InvalidAttempts_AccountLocked() throws UserException, ValidationException {
        // Arrange
        Login login = new Login();
        login.setEmail("test@example.com");
        login.setPassword("wrongPassword");

        User user = new User();
        user.setEmail("test@example.com");
        user.setPassword("encodedPassword");
        user.setLocked(false);
        user.setFailedTime(new Date(System.currentTimeMillis() - 60_000)); // Within continuous attempt duration

        LoginAttempt loginAttempt = new LoginAttempt();
        loginAttempt.setFailedAttempt(2);
        loginAttempt.setTime(new Date(System.currentTimeMillis() - 30_000)); // Within continuous attempt duration

        when(validationService.emailValidation(any())).thenReturn(true);
        when(userRepository.findByEmail(any())).thenReturn(user);
        when(loginAttemptRepository.findByUserId(any())).thenReturn(loginAttempt);

        // Act
        LoginResponse response = userRegisterServiceImple.signIn(login);

        // Assert
        assertNotNull(response);
        assertFalse(response.getSuccess());
        assertEquals("Too many wrong attempts your account is locked for 5 min.", response.getMessage());
    }
}