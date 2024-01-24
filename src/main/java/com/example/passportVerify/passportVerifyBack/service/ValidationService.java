package com.example.passportVerify.passportVerifyBack.service;

import com.example.passportVerify.passportVerifyBack.entity.User;
import com.example.passportVerify.passportVerifyBack.exception.ValidationException;
import com.example.passportVerify.passportVerifyBack.request.Login;
import com.example.passportVerify.passportVerifyBack.request.PassportDataRequest;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.regex.Pattern;

@Service
public class ValidationService implements Validation{
    @Value("${validation.signup.name.regEx}")
    private String validName;

    @Value("${validation.signup.number.regEx1}")
    private String validNumber;

    @Value("${validation.email.regEx2}")
    private String validEmail;

    @Value("${validation.passportNumber.regEx3}")
    private String validPassportNumber;

    @Value("${validation.address.regEx4}")
    private String validAddress;

    @Value("${validation.phoneNumber.regEx5}")
    private String validPhoneNumber;

    @Override
    public Boolean nameValidation(String name) throws ValidationException {

        return name.matches(validName);
    }

    @Override
    public Boolean emailValidation(String email) throws ValidationException {

        return email.matches(validEmail);
    }

    @Override
    public Boolean zipcodeValidation(String number) throws ValidationException {

        return number.matches(validNumber);
    }
    @Override
    public Boolean phoneNumberValidation(String number)throws ValidationException{
        return number.matches(validPhoneNumber);
    }
    @Override
    public Boolean passportNumberValidation(String number) throws ValidationException {

        return number.matches(validPassportNumber);
    }

    @Override
    public Boolean addressValidation(String address) throws ValidationException {

        return address.matches(validAddress);
    }


//    @Override
//    public Boolean sigupValidation(User user) throws ValidationException {
//        return (user.getFirstName().matches(name) && user.getLastName().matches(name) && user.getPhoneNumber().matches(number) && user.getEmail().matches(email));
//    }
//    @Override
//    public Boolean signinValidation(Login login)throws ValidationException{
//       return (login.getEmail().matches(email));
//    }
//
//    @Override
//    public Boolean verifyValidation(PassportDataRequest passportDataRequest) throws ValidationException {
//        return (passportDataRequest.getFirstName().matches(name) && passportDataRequest.getLastName().matches(name) && passportDataRequest.getPhoneNumber().matches(number) && passportDataRequest.getEmail().matches(email) && passportDataRequest.getAge().matches(number)
//                && passportDataRequest.getZipcode().matches(number)  &&
//                passportDataRequest.getCity().matches(name) && passportDataRequest.getState().matches(name) && passportDataRequest.getPassportNumber().matches(passportNumber));
//    }
}
