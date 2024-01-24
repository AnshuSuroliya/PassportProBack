package com.example.passportVerify.passportVerifyBack.repository;

import com.example.passportVerify.passportVerifyBack.entity.Address;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AddressRepository extends JpaRepository<Address,Long> {
}
