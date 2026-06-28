package com.modernisc.security.keycloak.users.dto;

import com.modernisc.security.keycloak.users.Role;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.Set;
import java.util.StringJoiner;

public class UserDto {

    private long id;
    private String username;
    private String password;
    private String description;
    private String employeeNumber;
    private String temporary;
    private int maxTryCount;
    private LocalDateTime passwordExpirationDate;
    private boolean credentialsExpired;
    private String enabled;
    private LocalDateTime createdTimeStamp;
    private LocalDateTime modifiedTimeStamp;
    private String firstName;
    private String lastName;
    private String email;
    private String emailVerified;

    private Set<Role> roles;

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getEmployeeNumber() {
        return employeeNumber;
    }

    public void setEmployeeNumber(String employeeNumber) {
        this.employeeNumber = employeeNumber;
    }

    public String getTemporary() {
        return temporary;
    }

    public void setTemporary(String temporary) {
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

    public LocalDateTime getPasswordExpirationDate() {
        return passwordExpirationDate;
    }

    public void setPasswordExpirationDate(LocalDateTime passwordExpirationDate) {
        this.passwordExpirationDate = passwordExpirationDate;
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

    public LocalDateTime getCreatedTimeStamp() {
        return createdTimeStamp;
    }

    public void setCreatedTimeStamp(LocalDateTime createdTimeStamp) {
        this.createdTimeStamp = createdTimeStamp;
    }

    public LocalDateTime getModifiedTimeStamp() {
        return modifiedTimeStamp;
    }

    public void setModifiedTimeStamp(LocalDateTime modifiedTimeStamp) {
        this.modifiedTimeStamp = modifiedTimeStamp;
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
        return new StringJoiner(", ", UserDto.class.getSimpleName() + "[", "]")
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
