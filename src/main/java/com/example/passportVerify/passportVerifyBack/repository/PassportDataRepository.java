package com.example.passportVerify.passportVerifyBack.repository;

import com.example.passportVerify.passportVerifyBack.entity.PassportData;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface PassportDataRepository extends JpaRepository<PassportData,Long> {
    @Query("Select p From PassportData p Where p.passportNumber=:passportNumber")
    PassportData findByNo(@Param("passportNumber") String passportNUmber);

    PassportData findByEmail(String email);
}
