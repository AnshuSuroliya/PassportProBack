package com.example.passportVerify.passportVerifyBack.service;

import com.example.passportVerify.passportVerifyBack.entity.PassportData;
import com.example.passportVerify.passportVerifyBack.exception.PassportException;
import com.example.passportVerify.passportVerifyBack.exception.ValidationException;
import com.example.passportVerify.passportVerifyBack.request.GetRequest;
import com.example.passportVerify.passportVerifyBack.request.PassportDataRequest;
import com.example.passportVerify.passportVerifyBack.response.PassportResponse;
import com.example.passportVerify.passportVerifyBack.response.VerificationResponse;
import net.sourceforge.tess4j.TesseractException;


import java.io.IOException;

public interface PassportService {
    public VerificationResponse registerPassport(PassportDataRequest passportDataRequest)
            throws TesseractException, IOException, ValidationException;
    public PassportResponse getPassport(GetRequest getRequest)throws PassportException;
}
