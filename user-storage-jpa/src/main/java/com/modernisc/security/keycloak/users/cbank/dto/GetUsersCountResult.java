package com.modernisc.security.keycloak.users.cbank.dto;

import java.util.StringJoiner;

public class GetUsersCountResult {

    private Long userCount;

    public Long getUserCount() {
        return userCount;
    }

    public void setUserCount(Long userCount) {
        this.userCount = userCount;
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", "[", "]")
                .add("userCount=" + userCount)
                .toString();
    }
}
