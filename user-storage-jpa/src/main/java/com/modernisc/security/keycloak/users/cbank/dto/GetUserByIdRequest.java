package com.modernisc.security.keycloak.users.cbank.dto;

import java.util.StringJoiner;

public class GetUserByIdRequest {

    private long persistenceId;

    public long getPersistenceId() {
        return persistenceId;
    }

    public void setPersistenceId(long persistenceId) {
        this.persistenceId = persistenceId;
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", "[", "]")
                .add("persistenceId=" + persistenceId)
                .toString();
    }
}
