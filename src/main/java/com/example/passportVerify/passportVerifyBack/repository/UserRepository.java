package com.example.passportVerify.passportVerifyBack.repository;

import com.example.passportVerify.passportVerifyBack.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User,Long> {
 User findByEmail(String email);
}
