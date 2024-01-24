package com.example.passportVerify.passportVerifyBack.service;

import com.example.passportVerify.passportVerifyBack.entity.User;
import com.example.passportVerify.passportVerifyBack.exception.ValidationException;
import com.example.passportVerify.passportVerifyBack.request.Login;
import com.example.passportVerify.passportVerifyBack.request.PassportDataRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
@ExtendWith(MockitoExtension.class)
class ValidationServiceTest {


    @Value("${validation.signup.name.regEx}")
    private String nameRegEx;

    @Value("${validation.signup.number.regEx1}")
    private String numberRegEx;

    @Value("${validation.email.regEx2}")
    private String emailRegEx;

    @Value("${validation.passportNumber.regEx3}")
    private String passportNumberRegEx;

    @InjectMocks
    private ValidationService validationService;

//    @BeforeEach
//    void setUp() {
//        MockitoAnnotations.openMocks(this);
//    }
    @Test
    public void testValidNameValidation() throws ValidationException {
        ReflectionTestUtils.setField(validationService, "validName", "^[A-Za-z]+$");
        assertTrue(validationService.nameValidation("John"));
    }

    @Test
    public void testInvalidNameValidation() throws ValidationException {
        ReflectionTestUtils.setField(validationService, "validName", "^[A-Za-z]+$");
        assertFalse(validationService.nameValidation("123"));
    }

    @Test
    public void testValidEmailValidation() throws ValidationException {
        ReflectionTestUtils.setField(validationService, "validEmail", "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$");
        assertTrue(validationService.emailValidation("test@example.com"));
    }

    @Test
    public void testInvalidEmailValidation() throws ValidationException {
        ReflectionTestUtils.setField(validationService, "validEmail", "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$");
        assertFalse(validationService.emailValidation("asad.hgahda.sdha"));
    }

    @Test
    public void testValidPhoneNumberValidation() throws ValidationException {
        ReflectionTestUtils.setField(validationService, "validPhoneNumber", "^[9876]\\d{9}$");
        assertTrue(validationService.phoneNumberValidation("8976564000"));
    }

    @Test
    public void testInvalidPhoneNumberValidation() throws ValidationException {
        ReflectionTestUtils.setField(validationService, "validPhoneNumber", "^[9876]\\d{9}$");
        assertFalse(validationService.phoneNumberValidation("dgshdhs"));
    }
    @Test
    public void testValidZipcodeValidation() throws ValidationException {
        ReflectionTestUtils.setField(validationService, "validNumber", "^[0-9]+$");
        assertTrue(validationService.zipcodeValidation("302029"));
    }

    @Test
    public void testInvalidZipcodeValidation() throws ValidationException {
        ReflectionTestUtils.setField(validationService, "validNumber", "^[0-9]+$");
        assertFalse(validationService.zipcodeValidation("dgshdhs"));
    }
    @Test
    public void testValidPassportNumberValidation() throws ValidationException {
        ReflectionTestUtils.setField(validationService, "validPassportNumber", "^[A-Z0-9]+$");
        assertTrue(validationService.passportNumberValidation("AB1234567"));
    }

    @Test
    public void testInvalidPassportNumberValidation() throws ValidationException {
        ReflectionTestUtils.setField(validationService, "validPassportNumber", "^[A-Z0-9]+$");
        assertFalse(validationService.passportNumberValidation("dghsd"));
    }

    @Test
    public void testValidAddressValidation() throws ValidationException {
        ReflectionTestUtils.setField(validationService, "validAddress", "^[A-Za-z0-9,.\\s]+$");
        assertTrue(validationService.addressValidation("123 Street, City"));
    }

    @Test
    public void testInvalidAddressValidation() throws ValidationException {
        ReflectionTestUtils.setField(validationService, "validAddress", "^[A-Za-z0-9,.\\s]+$");
       assertFalse(validationService.addressValidation("@dh%fs"));
    }
//    @Test
//    void nameValidation_ValidName_ReturnsTrue() throws ValidationException {
//        when(validationService.nameValidation("JohnDoe")).thenReturn(true);
//        assertTrue(validationService.nameValidation("JohnDoe"));
//    }
//
//    @Test
//    void nameValidation_InvalidName_ReturnsFalse() throws ValidationException {
//        when(validationService.nameValidation("123")).thenReturn(false);
//        assertFalse(validationService.nameValidation("123"));
//    }
//
//    @Test
//    void emailValidation_ValidEmail_ReturnsTrue() throws ValidationException {
//        when(validationService.emailValidation("john.doe@example.com")).thenReturn(true);
//        assertTrue(validationService.emailValidation("john.doe@example.com"));
//    }
//
//    @Test
//    void emailValidation_InvalidEmail_ReturnsFalse() throws ValidationException {
//        when(validationService.emailValidation("invalid-email")).thenReturn(false);
//        assertFalse(validationService.emailValidation("invalid-email"));
//    }
//
//    @Test
//    void phoneNumberValidation_ValidNumber_ReturnsTrue() throws ValidationException {
//        when(validationService.phoneNumberValidation("1234567890")).thenReturn(true);
//        assertTrue(validationService.phoneNumberValidation("1234567890"));
//    }
//
//    @Test
//    void phoneNumberValidation_InvalidNumber_ReturnsFalse() throws ValidationException {
//        when(validationService.phoneNumberValidation("invalid-number")).thenReturn(false);
//        assertFalse(validationService.phoneNumberValidation("invalid-number"));
//    }
//
//    @Test
//    void passportNumberValidation_ValidPassportNumber_ReturnsTrue() throws ValidationException {
//        when(validationService.passportNumberValidation("AB123456")).thenReturn(true);
//        assertTrue(validationService.passportNumberValidation("AB123456"));
//    }
//
//    @Test
//    void passportNumberValidation_InvalidPassportNumber_ReturnsFalse() throws ValidationException {
//       when(validationService.passportNumberValidation("invalid-passport-number")).thenReturn(false);
//        assertFalse(validationService.passportNumberValidation("invalid-passport-number"));
//    }
//
//    @Test
//    void addressValidation_ValidAddress_ReturnsTrue() throws ValidationException {
//       when(validationService.addressValidation("123 Main St")).thenReturn(true);
//        assertTrue(validationService.addressValidation("123 Main St"));
//    }
//
//    @Test
//    void addressValidation_InvalidAddress_ReturnsFalse() throws ValidationException {
//        when(validationService.addressValidation("invalid_address")).thenReturn(false);
//        assertFalse(validationService.addressValidation("invalid_address"));
//    }

//    private ValidationService validationService = new ValidationService();
//
//    @Test
//    void testSignupValidation_ValidUser() throws ValidationException {
//        // Arrange
//        User user = new User();
//        user.setFirstName("John");
//        user.setLastName("Doe");
//        user.setPhoneNumber("1234567890");
//        user.setEmail("johndoe@example.com");
//
//        // Act and Assert
//        assertTrue(validationService.sigupValidation(user));
//    }
//
//    @Test
//    void testSignupValidation_InvalidFirstName() {
//        // Arrange
//        User user = new User();
//        user.setFirstName("123");
//
//        // Act and Assert
//        assertThrows(ValidationException.class, () -> validationService.sigupValidation(user));
//    }
//
//    @Test
//    void testSigninValidation_ValidLogin() throws ValidationException {
//        // Arrange
//        Login login = new Login();
//        login.setEmail("john.doe@example.com");
//
//        // Act and Assert
//        assertTrue(validationService.signinValidation(login));
//    }
//
//    @Test
//    void testSigninValidation_InvalidEmail() {
//        // Arrange
//        Login login = new Login();
//        login.setEmail("invalid-email");
//
//        // Act and Assert
//        assertThrows(ValidationException.class, () -> validationService.signinValidation(login));
//    }
//
//    @Test
//    void testVerifyValidation_ValidPassportDataRequest() throws ValidationException {
//        // Arrange
//        PassportDataRequest passportDataRequest = new PassportDataRequest();
//        passportDataRequest.setFirstName("John");
//        passportDataRequest.setLastName("Doe");
//        passportDataRequest.setPhoneNumber("1234567890");
//        passportDataRequest.setEmail("john.doe@example.com");
//        passportDataRequest.setAge("25");
//        passportDataRequest.setZipcode("12345");
//        passportDataRequest.setCity("City");
//        passportDataRequest.setState("State");
//        passportDataRequest.setPassportNumber("AB123456");
//
//        // Act and Assert
//        assertTrue(validationService.verifyValidation(passportDataRequest));
//    }
//
//    @Test
//    void testVerifyValidation_InvalidFirstName() {
//        // Arrange
//        PassportDataRequest passportDataRequest = new PassportDataRequest();
//        passportDataRequest.setFirstName("123");
//
//        // Act and Assert
//        assertThrows(ValidationException.class, () -> validationService.verifyValidation(passportDataRequest));
//    }
//
//    @Test
//    void testConstructor_InjectValues() {
//        // Arrange
//
//        ReflectionTestUtils.setField(validationService, "name", "^[a-zA-Z]+$");
//        ReflectionTestUtils.setField(validationService, "number", "^[0-9]+$");
//        ReflectionTestUtils.setField(validationService, "email", "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\\\.[a-zA-Z]{2,}$");
//        ReflectionTestUtils.setField(validationService, "passportNumber", "^[A-Z0-9]+$");
//        ReflectionTestUtils.setField(validationService, "address", "^[a-zA-Z0-9\\s.,#-]+$");
//
//        // Act and Assert
//        assertEquals("^[a-zA-Z]+$", ReflectionTestUtils.getField(validationService, "name"));
//        assertEquals("^[0-9]+$", ReflectionTestUtils.getField(validationService, "number"));
//        assertEquals("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\\\.[a-zA-Z]{2,}$", ReflectionTestUtils.getField(validationService, "email"));
//        assertEquals("^[A-Z0-9]+$", ReflectionTestUtils.getField(validationService, "passportNumber"));
//        assertEquals("^[a-zA-Z0-9\\s.,#-]+$", ReflectionTestUtils.getField(validationService, "address"));
//    }
//    @Test
//    public void testSignupValidationAllValid() throws ValidationException {
//
//
//        User user = new User();
//
//        user.setFirstName("hsdd");
//        user.setLastName("dhsd");
//        user.setEmail("test@gmail.com");
//        user.setPassword("Test@123");
//        ValidationService mockValidationService = mock(ValidationService.class);
//        when(mockValidationService.sigupValidation(user)).thenReturn(true);
//
//
//        boolean result = mockValidationService.sigupValidation(user);
//
//
//        assertTrue(result);
//    }
//
//    @Test
//    public void testSignupValidationInvalidFirstName() throws ValidationException {
//
//
//        User user = new User();
//
//        user.setFirstName("hs78");
//        user.setLastName("dhsd");
//        user.setEmail("test@gmail.com");
//        user.setPhoneNumber("362323273");
//        user.setPassword("Test@123");
//
//        ValidationService mockValidationService = mock(ValidationService.class);
//        when(mockValidationService.sigupValidation(user)).thenReturn(false);
//
//
//        boolean result = mockValidationService.sigupValidation(user);
//
//
//        assertFalse(result);
//    }
//
//    @Test
//    public void testSignupValidationInvalidLastName() throws ValidationException {
//
//
//        User user = new User();
//
//        user.setFirstName("hsdd");
//        user.setLastName("dhsd878");
//        user.setEmail("test@gmail.com");
//        user.setPhoneNumber("323626723");
//        user.setPassword("Test@123");
//
//        ValidationService mockValidationService = mock(ValidationService.class);
//        when(mockValidationService.sigupValidation(user)).thenReturn(false);
//
//
//        boolean result = mockValidationService.sigupValidation(user);
//
//
//        assertFalse(result);
//    }
//
//    @Test
//    public void testSignupValidationInvalidPhoneNumber() throws ValidationException {
//
//
//
//        User user = new User();
//
//        user.setFirstName("hsdd");
//        user.setLastName("dhsd");
//        user.setEmail("test@gmail.com");
//        user.setPhoneNumber("hddjsd");
//        user.setPassword("Test@123");
//
//        ValidationService mockValidationService = mock(ValidationService.class);
//        when(mockValidationService.sigupValidation(user)).thenReturn(false);
//
//
//        boolean result = mockValidationService.sigupValidation(user);
//
//
//        assertFalse(result);
//    }
//
//    @Test
//    public void testSignupValidationInvalidEmail() throws ValidationException {
//
//
//        User user = new User();
//        user.setFirstName("hsdd");
//        user.setLastName("dhsd");
//        user.setEmail("test.gmail.com");
//        user.setPhoneNumber("73264334423");
//        user.setPassword("Test@123");
//        ValidationService mockValidationService = mock(ValidationService.class);
//        when(mockValidationService.sigupValidation(user)).thenReturn(false);
//
//
//        boolean result = mockValidationService.sigupValidation(user);
//
//
//        assertFalse(validationService.sigupValidation(user));
//    }
//    @Test
//    void signinValidation_ValidLogin_ReturnsTrue() throws ValidationException {
//        Login login = new Login("john@example.com", "password");
//        ValidationService mockValidationService = mock(ValidationService.class);
//        when(mockValidationService.signinValidation(login)).thenReturn(true);
//
//
//        boolean result = mockValidationService.signinValidation(login);
//
//
//        assertTrue(result);
//    }
//
//    @Test
//    void signinValidation_InvalidLogin() throws ValidationException {
//
//        ValidationService validationService = new ValidationService(); // You may use Mockito to mock dependencies
//        Login login = new Login("invalidEmail", "password");
//
//
//        ValidationService mockValidationService = mock(ValidationService.class);
//        when(mockValidationService.signinValidation(login)).thenReturn(false);
//
//
//        boolean result = mockValidationService.signinValidation(login);
//
//
//        assertFalse(result);
//    }
//    @Test
//    void sigupValidation_ValidUser_ReturnsTrue() throws ValidationException {
//        User user = new User();
//        user.setFirstName("hsdd");
//        user.setLastName("dhsd");
//        user.setEmail("test@gmail.com");
//        user.setPassword("Test@123");
//        when(validationService.sigupValidation(user)).thenReturn(true);
//
//        assertTrue(validationService.sigupValidation(user));
//    }
//
//    @Test
//    void sigupValidation_InvalidUser_ReturnsFalse() throws ValidationException {
//        User user = new User();
//        user.setFirstName("2373");
//        user.setLastName("dhs382");
//        user.setEmail("test.gmail.com");
//        user.setPassword("Test@123");
//        when(validationService.sigupValidation(user)).thenReturn(false);
//
//        assertFalse(validationService.sigupValidation(user));
//    }
//
//    @Test
//    void signinValidation_ValidLogin_ReturnsTrue() throws ValidationException {
//        Login login = new Login("john@example.com", "password");
//        when(validationService.signinValidation(login)).thenReturn(true);
//
//        assertTrue(validationService.signinValidation(login));
//    }
//
//    @Test
//    void signinValidation_InvalidLogin_ReturnsFalse() throws ValidationException {
//        Login login = new Login("invalidEmail", "password");
//        when(validationService.signinValidation(login)).thenReturn(false);
//
//        assertFalse(validationService.signinValidation(login));
//    }
//
//    @Test
//    void verifyValidation_ValidPassportDataRequest_ReturnsTrue() throws ValidationException {
//        PassportDataRequest request = new PassportDataRequest("John", "Doe", "sdsdsjd","hdsdsjd", "shdsjdjs", "sdgjsad","hsdsd","32" ,"37823823", "test@gmail.com", "12345",null);
//        when(validationService.verifyValidation(request)).thenReturn(true);
//
//        assertTrue(validationService.verifyValidation(request));
//    }
//
//    @Test
//    void verifyValidation_InvalidPassportDataRequest_ReturnsFalse() throws ValidationException {
//        PassportDataRequest request = new PassportDataRequest("627", "Do9", "sdsdsjd","hdsdsjd", "shd26sjdjs", "sdgjsad","hsdsd","32" ,"37823823", "test@gmail.com", "12345",null);
//        when(validationService.verifyValidation(request)).thenReturn(false);
//
//        assertFalse(validationService.verifyValidation(request));
//    }


}