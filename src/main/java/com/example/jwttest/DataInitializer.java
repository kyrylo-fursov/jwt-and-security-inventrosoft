package com.example.jwttest;

import com.example.jwttest.entity.UserInfo;
import com.example.jwttest.service.UserInfoService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class DataInitializer implements CommandLineRunner {

    private final UserInfoService userInfoService;

    public DataInitializer(UserInfoService userInfoService) {
        this.userInfoService = userInfoService;
    }

    @Override
    public void run(String... args) {
        // Create default users
        UserInfo user1 = new UserInfo(1, "user1", "user1@email.com", "1234", "ROLE_USER");
        UserInfo user2 = new UserInfo(2, "user2", "user2@email.com", "1234", "ROLE_USER");
        UserInfo user3 = new UserInfo(3, "admin", "admin@email.com", "1234", "ROLE_USER, ROLE_ADMIN");

        userInfoService.addUser(user1);
        userInfoService.addUser(user2);
        userInfoService.addUser(user3);
    }
}
