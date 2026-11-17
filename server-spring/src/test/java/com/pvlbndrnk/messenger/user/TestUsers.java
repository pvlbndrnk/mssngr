package com.pvlbndrnk.messenger.user;

import org.springframework.test.util.ReflectionTestUtils;

import java.util.UUID;

public final class TestUsers {
    private TestUsers() {}
    public static User create(String username, String password) {
        User user = User.create(username, password);
        ReflectionTestUtils.setField(user, "id", UUID.randomUUID());
        return user;
    }
}
