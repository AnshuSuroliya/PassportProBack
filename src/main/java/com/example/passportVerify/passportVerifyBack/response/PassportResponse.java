package com.example.passportVerify.passportVerifyBack.response;

import com.example.passportVerify.passportVerifyBack.entity.PassportData;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
public class PassportResponse {
    private PassportData passportData;
    private Boolean success;
}
