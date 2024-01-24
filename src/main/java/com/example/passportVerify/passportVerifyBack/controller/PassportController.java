package com.example.passportVerify.passportVerifyBack.controller;

import com.example.passportVerify.passportVerifyBack.exception.PassportException;
import com.example.passportVerify.passportVerifyBack.exception.ValidationException;
import com.example.passportVerify.passportVerifyBack.request.GetRequest;
import com.example.passportVerify.passportVerifyBack.request.PassportDataRequest;
import com.example.passportVerify.passportVerifyBack.response.PassportResponse;
import com.example.passportVerify.passportVerifyBack.response.VerificationResponse;
import com.example.passportVerify.passportVerifyBack.service.PassportServiceImple;
import net.sourceforge.tess4j.TesseractException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


import java.io.IOException;

@RestController
@RequestMapping("/v1/api")
public class PassportController {
	@Autowired
	PassportServiceImple passportServiceImple;

	@PostMapping(path="/verify",consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
	public ResponseEntity<VerificationResponse> verify(
													   @ModelAttribute PassportDataRequest passportDataRequest
			) throws TesseractException, IOException, ValidationException {
		return new ResponseEntity<>(passportServiceImple.registerPassport(passportDataRequest),
				HttpStatus.ACCEPTED);
	}
	@PostMapping("/profile")
	public ResponseEntity<PassportResponse> fetchData(@RequestBody GetRequest getRequest)throws PassportException {
		return new ResponseEntity<>(passportServiceImple.getPassport(getRequest),HttpStatus.OK);
	}
}
