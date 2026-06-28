package com.modernisc.security.keycloak.iam.dto;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.modernisc.security.keycloak.iam.util.IsoInstantLocalDateTimeSerializer;

import java.util.Date;
import java.util.StringJoiner;

public class UserInfo {

    private long id;
    private String username;
    private String uuid;
    private int maxTryCount;
    @JsonSerialize(using = IsoInstantLocalDateTimeSerializer.class)
    private Date passwordExpirationDate;
    private boolean credentialsExpired;
    private String enabled;

    private Date createdTimeStamp;

    private Date modifiedTimeStamp;
    private String firstName;
    private String lastName;
    private String email;
    private String emailVerified;
    private Boolean temporary;

    public Date getPasswordExpirationDate() {
        return passwordExpirationDate;
    }

    public void setPasswordExpirationDate(Date passwordExpirationDate) {
        this.passwordExpirationDate = passwordExpirationDate;
    }

    public Date getCreatedTimeStamp() {
        return createdTimeStamp;
    }

    public void setCreatedTimeStamp(Date createdTimeStamp) {
        this.createdTimeStamp = createdTimeStamp;
    }

    public Date getModifiedTimeStamp() {
        return modifiedTimeStamp;
    }

    public void setModifiedTimeStamp(Date modifiedTimeStamp) {
        this.modifiedTimeStamp = modifiedTimeStamp;
    }

    public String getUuid() {
        return uuid;
    }

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }

    public Boolean getTemporary() {
        return temporary;
    }

    public void setTemporary(Boolean temporary) {
        this.temporary = temporary;
    }


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


    public boolean isCredentialsExpired() {
        return credentialsExpired;
    }

    public void setCredentialsExpired(boolean credentialsExpired) {
        this.credentialsExpired = credentialsExpired;
    }

    public String getEnabled() {
        return enabled;
    }

    public void setEnabled(String enabled) {
        this.enabled = enabled;
    }


    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getEmailVerified() {
        return emailVerified;
    }

    public void setEmailVerified(String emailVerified) {
        this.emailVerified = emailVerified;
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", UserInfo.class.getSimpleName() + "[", "]")
                .add("id=" + id)
                .add("username='" + username + "'")
                .add("maxTryCount=" + maxTryCount)
                .add("passwordExpirationDate=" + passwordExpirationDate)
                .add("credentialsExpired=" + credentialsExpired)
                .add("enabled='" + enabled + "'")
                .add("createdTimeStamp=" + createdTimeStamp)
                .add("modifiedTimeStamp=" + modifiedTimeStamp)
                .add("firstName='" + firstName + "'")
                .add("lastName='" + lastName + "'")
                .add("email='" + email + "'")
                .add("emailVerified='" + emailVerified + "'")
                .toString();
    }
}
