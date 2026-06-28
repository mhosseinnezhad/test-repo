package com.modernisc.security.keycloak.iam.dto;

import java.util.StringJoiner;

public class LoginRequest {

    private String clientPassword;
    private String clientUsername;

    public String getClientPassword() {
        return clientPassword;
    }

    public void setClientPassword(String clientPassword) {
        this.clientPassword = clientPassword;
    }

    public String getClientUsername() {
        return clientUsername;
    }

    public void setClientUsername(String clientUsername) {
        this.clientUsername = clientUsername;
    }

    @Override
    public String toString() {
        return new StringJoiner(", ",  "[", "]")
                .add("clientUsername='" + clientUsername + "'")
                .toString();
    }
}
