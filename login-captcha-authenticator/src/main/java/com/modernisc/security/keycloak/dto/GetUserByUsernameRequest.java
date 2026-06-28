package com.modernisc.security.keycloak.dto;


import java.util.StringJoiner;

public class GetUserByUsernameRequest {

    private String userName;

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", "[", "]")
                .add("userName='" + userName + "'")
                .toString();
    }
}
