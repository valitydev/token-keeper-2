package com.rbkmoney.token.keeper;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.ServletComponentScan;

@ServletComponentScan
@SpringBootApplication(scanBasePackages = {"com.rbkmoney.token.keeper"})
public class TokenKeeperApplication {

    public static void main(String[] args) {
        SpringApplication.run(TokenKeeperApplication.class, args);
    }
}
