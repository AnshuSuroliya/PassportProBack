package com.example.passportVerify.passportVerifyBack;


import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(classes = PassportVerifyBackApplication.class)
class PassportVerifyBackApplicationTests {

    @Test
    void contextLoads() {

    }
    @Test
    void mainMethodRunsSuccessfully() {

        PassportVerifyBackApplication.main(new String[]{});
    }
}
