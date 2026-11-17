package com.pvlbndrnk.messenger.user;

import org.springframework.test.util.ReflectionTestUtils;

import java.util.UUID;

public class TestUsers {
    public static User create(String username, String password) {
        User user = User.create(username, password);
        ReflectionTestUtils.setField(user, "id", UUID.randomUUID());
        return user;
    }
}
