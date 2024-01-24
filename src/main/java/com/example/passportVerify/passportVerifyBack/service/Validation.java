package com.example.passportVerify.passportVerifyBack.service;

import com.example.passportVerify.passportVerifyBack.entity.User;
import com.example.passportVerify.passportVerifyBack.exception.ValidationException;
import com.example.passportVerify.passportVerifyBack.request.Login;
import com.example.passportVerify.passportVerifyBack.request.PassportDataRequest;


public interface Validation {
    public Boolean nameValidation(String name) throws ValidationException;
    public Boolean emailValidation(String email) throws ValidationException;
    public Boolean zipcodeValidation(String number) throws ValidationException;
    public Boolean phoneNumberValidation(String number)throws ValidationException;
    public Boolean passportNumberValidation(String number) throws ValidationException;
    public Boolean addressValidation(String address) throws ValidationException;
//    public Boolean sigupValidation(User user) throws ValidationException;
//    public Boolean signinValidation(Login login)throws ValidationException;
//    public Boolean verifyValidation(PassportDataRequest passportDataRequest)throws ValidationException;
}
