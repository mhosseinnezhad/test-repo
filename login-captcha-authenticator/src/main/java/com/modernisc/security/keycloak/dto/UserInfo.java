package com.modernisc.security.keycloak.dto;


import java.util.Date;
import java.util.StringJoiner;

public class UserInfo {

    private long id;
    private String username;
    private int maxTryCount;
    private Date passwordExpirationDate;
    private boolean credentialsExpired;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public int getMaxTryCount() {
        return maxTryCount;
    }

    public void setMaxTryCount(int maxTryCount) {
        this.maxTryCount = maxTryCount;
    }

    public Date getPasswordExpirationDate() {
        return passwordExpirationDate;
    }

    public void setPasswordExpirationDate(Date passwordExpirationDate) {
        this.passwordExpirationDate = passwordExpirationDate;
    }

    public boolean isCredentialsExpired() {
        return credentialsExpired;
    }

    public void setCredentialsExpired(boolean credentialsExpired) {
        this.credentialsExpired = credentialsExpired;
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", "[", "]")
                .add("id=" + id)
                .add("username='" + username + "'")
                .add("maxTryCount=" + maxTryCount)
                .add("passwordExpirationDate=" + passwordExpirationDate)
                .add("credentialsExpired=" + credentialsExpired)
                .toString();
    }
}
