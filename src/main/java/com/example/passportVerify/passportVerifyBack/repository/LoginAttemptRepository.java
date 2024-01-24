package com.example.passportVerify.passportVerifyBack.repository;

import com.example.passportVerify.passportVerifyBack.entity.LoginAttempt;
import com.example.passportVerify.passportVerifyBack.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface LoginAttemptRepository extends JpaRepository<LoginAttempt,Long> {
    @Query("Select u from LoginAttempt u Where u.user=:user")
    public LoginAttempt findByUserId(@Param("user") User user);

}
