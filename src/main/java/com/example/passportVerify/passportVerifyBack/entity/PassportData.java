package com.example.passportVerify.passportVerifyBack.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToOne;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.sql.Date;


@Entity
@Setter
@Getter
@NoArgsConstructor

public class PassportData {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;
	@NotNull
	private String firstName;
	@NotNull
	private String lastName;
	@NotNull
	@OneToOne
	private Address address;
	@NotNull
	private Date dob;
	@NotNull
	private String phoneNumber;
	@NotNull
	private String email;
	@NotNull
	private String passportNumber;
	@NotNull
	private Date validity;

}
