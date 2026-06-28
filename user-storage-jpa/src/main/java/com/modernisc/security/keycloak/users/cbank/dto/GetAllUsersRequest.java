package com.modernisc.security.keycloak.users.cbank.dto;

import java.util.StringJoiner;

public class GetAllUsersRequest {

    private int firstResult;
    private int maxResults;

    public int getFirstResult() {
        return firstResult;
    }

    public void setFirstResult(int firstResult) {
        this.firstResult = firstResult;
    }

    public int getMaxResults() {
        return maxResults;
    }

    public void setMaxResults(int maxResults) {
        this.maxResults = maxResults;
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", "[", "]")
                .add("firstResult=" + firstResult)
                .add("maxResults=" + maxResults)
                .toString();
    }
}
