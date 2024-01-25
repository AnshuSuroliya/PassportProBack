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
import jakarta.security.auth.message.AuthException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.auditing.CurrentDateTimeProvider;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Calendar;
import java.util.Date;

@Slf4j
@Service
public class UserRegisterServiceImple implements UserServiceRegister{
    @Autowired
    UserRepository userRepository;
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    JwtService jwtService;

    @Autowired
    ValidationService validationService;

    @Autowired
    LoginAttemptRepository loginAttemptRepository;


    private Long continiousAttempDuration=60*60*1000L;

    private Long lockDuration=5*60*1000L;
@Override
    public SignupResponse signUp(User user) throws UserException, ValidationException {
        if(validationService.nameValidation(user.getFirstName()) && validationService.nameValidation(user.getLastName()) && validationService.emailValidation(user.getEmail()) && validationService.phoneNumberValidation(user.getPhoneNumber())) {
            try {
                User user1 = userRepository.findByEmail(user.getEmail().toLowerCase());
                BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
                if (user1 == null) {
                    User u = new User();
                    u.setFirstName(user.getFirstName());
                    u.setLastName(user.getLastName());
                    u.setEmail(user.getEmail().toLowerCase());
                    u.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
                    u.setPhoneNumber(user.getPhoneNumber());
                    userRepository.save(u);
                    SignupResponse signupResponse = new SignupResponse("User Registered Successfully",true);
                    log.info("User Registered successfully");
                    return signupResponse;
                } else {
                    SignupResponse signupResponse1 = new SignupResponse("User Already Present",false);
                    log.info("User Already Present");
                    return signupResponse1;
                }
            }catch (Exception e){
                log.error("Error in creating account",e);
                SignupResponse signupResponse=new SignupResponse("Some error occured in creating account",false);
                return new ResponseEntity<SignupResponse>(signupResponse, HttpStatus.OK).getBody();
            }
        } else {
            log.info("Provided input syntax in incorrect");
            SignupResponse signupResponse=new SignupResponse("Provided input syntax is incorrect",false);
            return signupResponse;
        }
    }
    @Override
    public LoginResponse signIn(Login login) throws UserException,ValidationException{
            if(validationService.emailValidation(login.getEmail())) {

                    User user = userRepository.findByEmail(login.getEmail().toLowerCase());
                    Date currentDate= Calendar.getInstance().getTime();
                    if (user == null) {
                        LoginResponse loginResponse = new LoginResponse(false, null, "Wrong Email",null);
                        log.info("Wrong Email");
                        return loginResponse;
                    }

//            if(!login.getEmail().equals(user.getEmail())){
//                LoginResponse loginResponse=new LoginResponse(false,null,"Wrong Email");
//                return loginResponse;
//            }

                    try {
                        if(user.getLocked() && currentDate.getTime()-user.getFailedTime().getTime()<lockDuration){

                        log.info("Your account is Locked.Try after 5 min.");
                        LoginResponse loginResponse=new LoginResponse(false,null,"Your account is Locked!Try after 5 min.",null);
                        return loginResponse;
                    }
                            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(login.getEmail().toLowerCase(), login.getPassword()));
                            if (authentication.isAuthenticated()) {
                                String jwt = (jwtService.generateToken(login.getEmail().toLowerCase()));
                                user.setLocked(false);
                                user.setFailedTime(null);
                                LoginAttempt loginAttempt=loginAttemptRepository.findByUserId(user);
                                if(loginAttempt!=null) {
                                    loginAttempt.setUser(null);
                                    loginAttemptRepository.save(loginAttempt);
                                    loginAttemptRepository.delete(loginAttempt);
                                }
                                userRepository.save(user);
                                LoginResponse loginResponse = new LoginResponse(true, jwt, "Login Successfull!", login.getEmail().toLowerCase());
                                log.info("Login Successfull");
                                return loginResponse;
                            }
                            else {
                                LoginResponse loginResponse = new LoginResponse(false, null, "Wrong Password", null);
                                log.info("Wrong Password");
                                return loginResponse;
                            }

                    }catch (Exception e){
                        log.error("Wrong Password",e);
                        LoginAttempt loginAttempt=loginAttemptRepository.findByUserId(user);
                        long lastAttemptTime =lockDuration+1;
                        if(loginAttempt!=null){
                            Date lastAttempt = loginAttempt.getTime();
                            lastAttemptTime = currentDate.getTime() - lastAttempt.getTime();
                        }
                        if(loginAttempt==null || loginAttempt.getFailedAttempt()==0 || lastAttemptTime>continiousAttempDuration){
                            if(loginAttempt==null){
                                loginAttempt=new LoginAttempt();
                                loginAttempt.setUser(user);
                            }
                           loginAttempt.setFailedAttempt(1);
                            loginAttempt.setTime(currentDate);
                            loginAttemptRepository.save(loginAttempt);
                            LoginResponse loginResponse=new LoginResponse(false,null,"Wrong Password,Only 2 attempts left",null);
                            return loginResponse;
                        }
                        if(loginAttempt.getFailedAttempt()==1 && lastAttemptTime<continiousAttempDuration){
                            loginAttempt.setFailedAttempt(2);
                            loginAttempt.setTime(currentDate);
                            loginAttemptRepository.save(loginAttempt);
                            log.error("Wrong Password,Only 1 attempt left");
                            LoginResponse loginResponse=new LoginResponse(false,null,"Wrong Password,Only 1 attempt left",null);
                            return loginResponse;
                        }
                        if(loginAttempt.getFailedAttempt()==2 && lastAttemptTime<continiousAttempDuration){
                            user.setFailedTime(currentDate);
                            user.setLocked(true);
                            loginAttempt.setUser(null);
                            loginAttemptRepository.save(loginAttempt);
                            loginAttemptRepository.delete(loginAttempt);
                            userRepository.save(user);
                            log.error("Due to too many wrong attempts your account is locked for 5 min.");
                            LoginResponse loginResponse=new LoginResponse(false,null,"Too many wrong attempts your account is locked for 5 min.",null);
                            return loginResponse;
                        }
                        throw new UserException("Wrong Password");
//                        LoginResponse loginResponse=new LoginResponse(false,null,"error in login",null);
//                        return loginResponse;
                    }
            }
            else {
                log.info("Provided input syntax is wrong");
                LoginResponse loginResponse=new LoginResponse(false,null,"Provided input syntax is incorrect",null);
                return loginResponse;
            }
    }

    @Override
    public User getUser(GetRequest getRequest) throws UserException {
        User user=userRepository.findByEmail(getRequest.getEmail().toLowerCase());
        if(user==null){
            log.error("Error fetching user");
            throw new UserException("Error fetching user");
        }
        return user;
    }
}
