package com.example.passportVerify.passportVerifyBack.exception;

import com.example.passportVerify.passportVerifyBack.response.LoginResponse;
import com.example.passportVerify.passportVerifyBack.response.VerificationResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.mvc.support.DefaultHandlerExceptionResolver;

@ControllerAdvice
public class UserControllerHandler {


        @ExceptionHandler(value = UserException.class)
        public ResponseEntity<LoginResponse> handleInvalidCredentialsException(){
            LoginResponse loginResponse=new LoginResponse();
            loginResponse.setEmail(null);
            loginResponse.setJwt(null);
            loginResponse.setMessage("Wrong Password");
            loginResponse.setSuccess(false);
            return new ResponseEntity<>(loginResponse, HttpStatus.OK);
        }
        @ExceptionHandler(value = NullPointerException.class)
    public ResponseEntity<VerificationResponse> handleMapping(){
            VerificationResponse verificationResponse=new VerificationResponse();
            verificationResponse.setMessage("Provide all the fields");
            verificationResponse.setSuccess(false);
            return new ResponseEntity<>(verificationResponse,HttpStatus.OK);
        }
    }

