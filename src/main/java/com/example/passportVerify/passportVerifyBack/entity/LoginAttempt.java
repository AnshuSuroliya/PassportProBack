package com.example.passportVerify.passportVerifyBack.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.Date;

@Entity
@Getter
@Setter
@NoArgsConstructor
public class LoginAttempt {
    @Id
    @GeneratedValue
    private Long id;
    private int failedAttempt;
    private Date time;
    @OneToOne
    private User user;
}
