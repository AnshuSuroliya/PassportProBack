package com.example.passportVerify.passportVerifyBack.service;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

import com.example.passportVerify.passportVerifyBack.entity.Address;
import com.example.passportVerify.passportVerifyBack.exception.PassportException;
import com.example.passportVerify.passportVerifyBack.exception.ValidationException;
import com.example.passportVerify.passportVerifyBack.repository.AddressRepository;
import com.example.passportVerify.passportVerifyBack.request.GetRequest;
import com.example.passportVerify.passportVerifyBack.response.PassportResponse;
import com.example.passportVerify.passportVerifyBack.response.VerificationResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.example.passportVerify.passportVerifyBack.entity.PassportData;
import com.example.passportVerify.passportVerifyBack.repository.PassportDataRepository;
import com.example.passportVerify.passportVerifyBack.request.PassportDataRequest;

import lombok.extern.slf4j.Slf4j;
import net.sourceforge.tess4j.ITesseract;
import net.sourceforge.tess4j.TesseractException;
import org.springframework.web.multipart.MultipartFile;

import javax.imageio.ImageIO;

@Service
@Slf4j
public class PassportServiceImple implements PassportService{

	@Autowired
	PassportDataRepository passportDataRepository;

	@Autowired
	AddressRepository addressRepository;
	
	@Autowired
	ITesseract tesseract;

	@Autowired
	ValidationService validationService;

	@Override
	public VerificationResponse registerPassport(PassportDataRequest passportDataRequest)
			throws TesseractException, IOException , ValidationException {

			if(validationService.nameValidation(passportDataRequest.getFirstName()) && validationService.nameValidation(passportDataRequest.getLastName()) && validationService.emailValidation(passportDataRequest.getEmail()) && validationService.phoneNumberValidation(passportDataRequest.getPhoneNumber()) && validationService.passportNumberValidation(passportDataRequest.getPassportNumber()) && validationService.addressValidation(passportDataRequest.getAddressLine1()) && validationService.addressValidation(passportDataRequest.getAddressLine2()) && validationService.nameValidation(passportDataRequest.getState()) && validationService.nameValidation(passportDataRequest.getCity()) && validationService.zipcodeValidation(passportDataRequest.getZipcode())) {
				try {
					PassportData passportData0 = passportDataRepository.findByNo(passportDataRequest.getPassportNumber());
					PassportData passportData1=passportDataRepository.findByEmail(passportDataRequest.getEmail());

					if (passportData1==null && passportData0 == null) {
						InputStream inputStream = passportDataRequest.getPassportDoc().getInputStream();
						BufferedImage bufferedImage = ImageIO.read(inputStream);

						String result = tesseract.doOCR(bufferedImage).replace("[-+.^:,><'?_ !`~@#$%&*()]","").replace("/r","").replace("/n","").replace("\\s","").toUpperCase();
						log.info(result);
						log.info(String.valueOf(passportDataRequest.getDob()));
                        String dateString= String.valueOf(passportDataRequest.getDob());
						String validString= String.valueOf(passportDataRequest.getValidity());
						log.info(dateString);
                        LocalDate date=LocalDate.parse(dateString);
						LocalDate valid=LocalDate.parse(validString);
                        DateTimeFormatter formatter=DateTimeFormatter.ofPattern("dd/MM/yyyy");
                        String formattedDate=date.format(formatter);
						String validDate=valid.format(formatter);
						if (!result.contains(passportDataRequest.getFirstName().toUpperCase())) {
							log.error("Verification Failed due to First Name Does Not Match");
							VerificationResponse verificationResponse=new VerificationResponse("Verification Failed due to First Name Does Not Match",false);
							return verificationResponse;
						}
						if(!result.contains(passportDataRequest.getLastName().toUpperCase())) {
							log.error("Verification Failed due to Last Name Does Not Match");
							VerificationResponse verificationResponse=new VerificationResponse("Verification Failed due to Last Name does not match",false);
							return verificationResponse;
						}
						if(!result.contains(passportDataRequest.getPassportNumber())) {
							log.error("Verification Failed due to Passport Number Does Not Match");
							VerificationResponse verificationResponse=new VerificationResponse("Verification Failed due to Passport Number does not match",false);
							return verificationResponse;
						}
						if(!result.contains(passportDataRequest.getCity().toUpperCase())){
							log.error("Verification Failed due to city does not match");
							VerificationResponse verificationResponse=new VerificationResponse("Verification Failed due to city does not match",false);
							return verificationResponse;
						}
						if(!result.contains(passportDataRequest.getState().toUpperCase())){
							log.error("Verification failed due to state does not match");
							VerificationResponse verificationResponse=new VerificationResponse("Verification failed due to state does not match",false);
							return verificationResponse;
						}
                        if(!result.contains(formattedDate)){
							log.info(formattedDate);
                            log.error("Verification failed due to DOB does not match");
                            VerificationResponse verificationResponse=new VerificationResponse("Verification failed due to DOB does not match",false);
                            return verificationResponse;
                        }
//						if(!result.contains(validDate)){
//							log.info(formattedDate);
//							log.error("Provided validity date of your passport is incorrect");
//							VerificationResponse verificationResponse=new VerificationResponse("Provided validity date of your passport is incorrect",false);
//							return verificationResponse;
//						}
							PassportData passportData = new PassportData();
							passportData.setFirstName(passportDataRequest.getFirstName());
							passportData.setLastName(passportDataRequest.getLastName());
							passportData.setPassportNumber(passportDataRequest.getPassportNumber());
							passportData.setPhoneNumber(passportDataRequest.getPhoneNumber());
							passportData.setDob(passportDataRequest.getDob());
                            passportData.setValidity(passportDataRequest.getValidity());
							passportData.setEmail(passportDataRequest.getEmail());
							Address address=new Address();
							address.setAddressLine1(passportDataRequest.getAddressLine1());
							address.setAddressLine2(passportDataRequest.getAddressLine2());
							address.setCity(passportDataRequest.getCity());
							address.setState(passportDataRequest.getState());
							address.setZipcode(passportDataRequest.getZipcode());
							addressRepository.save(address);
							passportData.setAddress(address);
							passportDataRepository.save(passportData);
							VerificationResponse verificationResponse = new VerificationResponse("Verified and Registered Successfully",true);
							log.info("Verified and Registered Successfully");
							return verificationResponse;

					} else {
						VerificationResponse verificationResponse2 = new VerificationResponse("Registered Already",false);
						log.info("Registered Already");
						return verificationResponse2;
					}
				} catch (TesseractException e) {
					log.error("Error performing OCR", e);
					VerificationResponse verificationResponse=new VerificationResponse("Error in Extracting text from image",false);
					return verificationResponse;
				}catch(IOException e){
					log.error("error in verification",e);
					VerificationResponse verificationResponse=new VerificationResponse("Error in verification",false);
					return verificationResponse;
				}
			} else {
				log.info("Provided input syntax is incorrect");
				VerificationResponse verificationResponse=new VerificationResponse("Provided input syntax is incorrect",false);
				return verificationResponse;
			}

	}

	@Override
	public PassportResponse getPassport(GetRequest getRequest) throws PassportException {
		log.info(getRequest.getEmail());
		PassportData passportData=passportDataRepository.findByEmail(getRequest.getEmail());
		if(passportData==null){
			log.error("Error Fetching the details");
			PassportResponse passportResponse=new PassportResponse();
			passportResponse.setPassportData(null);
			passportResponse.setSuccess(false);
			return passportResponse;
		}
		PassportResponse passportResponse1=new PassportResponse();
		passportResponse1.setPassportData(passportData);
		passportResponse1.setSuccess(true);
		return passportResponse1;
	}
}
