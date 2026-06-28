package com.modernisc.security.keycloak.users.cbank.dto;

import java.util.StringJoiner;

public class RoleInfo {

    private long id;
    private String code;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", "[", "]")
                .add("id=" + id)
                .add("code='" + code + "'")
                .toString();
    }
}
