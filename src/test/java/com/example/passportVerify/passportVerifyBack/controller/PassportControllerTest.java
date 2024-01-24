package com.example.passportVerify.passportVerifyBack.controller;

import com.example.passportVerify.passportVerifyBack.entity.PassportData;
import com.example.passportVerify.passportVerifyBack.exception.PassportException;
import com.example.passportVerify.passportVerifyBack.exception.ValidationException;
import com.example.passportVerify.passportVerifyBack.request.GetRequest;
import com.example.passportVerify.passportVerifyBack.request.PassportDataRequest;
import com.example.passportVerify.passportVerifyBack.response.PassportResponse;
import com.example.passportVerify.passportVerifyBack.response.VerificationResponse;
import com.example.passportVerify.passportVerifyBack.service.PassportServiceImple;
import net.sourceforge.tess4j.TesseractException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.io.IOException;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class PassportControllerTest {

    @Mock
    private PassportServiceImple passportServiceImple;

    @InjectMocks
    private PassportController passportController;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }


    @Test
    void testVerify_Success() throws TesseractException, IOException, ValidationException {

        PassportDataRequest passportDataRequest = new PassportDataRequest();
        when(passportServiceImple.registerPassport(passportDataRequest)).thenReturn(new VerificationResponse("Verified and Registered Successfully",true));


        ResponseEntity<VerificationResponse> responseEntity = passportController.verify(passportDataRequest);


        assertEquals(HttpStatus.ACCEPTED, responseEntity.getStatusCode());
        assertEquals("Verified and Registered Successfully", Objects.requireNonNull(responseEntity.getBody()).getMessage());
        verify(passportServiceImple, times(1)).registerPassport(passportDataRequest);
    }

    @Test
    void testFetchData_Success() throws PassportException {

        GetRequest getRequest = new GetRequest();
        PassportData passportData=new PassportData();
        PassportResponse passportResponse=new PassportResponse();
        when(passportServiceImple.getPassport(getRequest)).thenReturn(passportResponse);


        ResponseEntity<?> responseEntity = passportController.fetchData(getRequest);


        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
        assertEquals(passportData, responseEntity.getBody());
        verify(passportServiceImple, times(1)).getPassport(getRequest);
    }

    @Test
    void testVerify_Failure() throws TesseractException, IOException, ValidationException {

        PassportDataRequest passportDataRequest = new PassportDataRequest();
        when(passportServiceImple.registerPassport(passportDataRequest)).thenThrow(new ValidationException("Validation failed"));


        ValidationException exception = org.junit.jupiter.api.Assertions.assertThrows(ValidationException.class, () -> {
            passportController.verify(passportDataRequest);
        });

        assertEquals("Validation failed", exception.getMessage());
        verify(passportServiceImple, times(1)).registerPassport(passportDataRequest);
    }
    @Test
    void testVerify_Failure_ValidationException() throws TesseractException, IOException, ValidationException {

        PassportDataRequest passportDataRequest = new PassportDataRequest();
        when(passportServiceImple.registerPassport(passportDataRequest)).thenThrow(new ValidationException("Validation failed"));


        ValidationException exception = assertThrows(ValidationException.class, () -> {
            passportController.verify(passportDataRequest);
        });

        assertEquals("Validation failed", exception.getMessage());
        verify(passportServiceImple, times(1)).registerPassport(passportDataRequest);
    }

    @Test
    void testVerify_Failure_IOException() throws TesseractException, IOException, ValidationException {

        PassportDataRequest passportDataRequest = new PassportDataRequest();
        when(passportServiceImple.registerPassport(passportDataRequest)).thenThrow(new IOException("IO error"));


        IOException exception = assertThrows(IOException.class, () -> {
            passportController.verify(passportDataRequest);
        });

        assertEquals("IO error", exception.getMessage());
        verify(passportServiceImple, times(1)).registerPassport(passportDataRequest);
    }

    @Test
    void testFetchData_Failure() throws PassportException {

        GetRequest getRequest = new GetRequest();
        when(passportServiceImple.getPassport(getRequest)).thenThrow(new PassportException("Passport not found"));


        PassportException exception = assertThrows(PassportException.class, () -> {
            passportController.fetchData(getRequest);
        });

        assertEquals("Passport not found", exception.getMessage());
        verify(passportServiceImple, times(1)).getPassport(getRequest);
    }
    @Test
    void testVerify_Failure_TesseractException() throws TesseractException, IOException, ValidationException {

        PassportDataRequest passportDataRequest = new PassportDataRequest();
        when(passportServiceImple.registerPassport(passportDataRequest)).thenThrow(new TesseractException("Tesseract error"));


        TesseractException exception = assertThrows(TesseractException.class, () -> {
            passportController.verify(passportDataRequest);
        });

        assertEquals("Tesseract error", exception.getMessage());
        verify(passportServiceImple, times(1)).registerPassport(passportDataRequest);
    }

}