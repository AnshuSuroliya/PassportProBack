package com.example.passportVerify.passportVerifyBack.request;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Login {
    private String email;
    private String password;

}
