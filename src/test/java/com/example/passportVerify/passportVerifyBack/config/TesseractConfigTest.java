package com.example.passportVerify.passportVerifyBack.config;

import net.sourceforge.tess4j.ITesseract;
import net.sourceforge.tess4j.Tesseract;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@TestPropertySource(properties = {
        "tesseract.path=/path/to/tessdata"
})
class TesseractConfigTest {
    @Value("${tesseract.path}")
    public String tessdatapath;
    @MockBean
    TesseractConfig tesseractConfig;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

}