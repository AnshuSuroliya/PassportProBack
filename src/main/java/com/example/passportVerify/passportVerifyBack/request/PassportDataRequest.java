package com.example.passportVerify.passportVerifyBack.request;


import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.web.multipart.MultipartFile;

import java.sql.Date;


@Getter
@Setter
@NoArgsConstructor

public class PassportDataRequest {
    private String firstName;
    private String lastName;
    private String addressLine1;
    private String addressLine2;
    private String state;
    private String city;
    private String zipcode;
    private Date dob;
    private String phoneNumber;
    private String email;
    private String passportNumber;
    private Date validity;
    private MultipartFile passportDoc;
}
