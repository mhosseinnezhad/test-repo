package com.modernisc.security.keycloak.iam.dto;

import java.util.StringJoiner;

public class RoleInfo {

    private Long id;
    private String code;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
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
