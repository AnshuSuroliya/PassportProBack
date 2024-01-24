package com.example.passportVerify.passportVerifyBack.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import net.sourceforge.tess4j.ITesseract;
import net.sourceforge.tess4j.Tesseract;

@Configuration
public class TesseractConfig {

	@Value("${tesseract.path}")
	private String tessdatapath;

	@Bean
	public ITesseract tesseract() {
		ITesseract tesseract=new Tesseract();		
		tesseract.setDatapath(tessdatapath);
		tesseract.setLanguage("eng");
        tesseract.setPageSegMode(1);
        tesseract.setOcrEngineMode(1);
		return tesseract;
	}
	
	
}