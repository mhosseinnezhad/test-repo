package com.modernisc.security.keycloak.users;

import jakarta.persistence.*;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.Set;

@NamedQueries({
        @NamedQuery(
                name = "getUserByUsername",
                query = "select u from User u where u.username = :username"),
        @NamedQuery(
                name = "getUserByEmail",
                query = "select u from User u where u.email = :email"),
        @NamedQuery(
                name = "getUserCount",
                query = "select count(u) from User u"),
        @NamedQuery(
                name = "getAllUsers",
                query = "select u from User u"),
        @NamedQuery(
                name = "searchForUser",
                query = "select u from User u where " +
                        "( lower(u.username) like :search or u.email like :search ) " +
                        "order by u.username"),
        @NamedQuery(
                name = "getUserByEmployeeNumber",
                query = "SELECT u FROM User u WHERE u.employeeNumber = :employeeNumber"
        )

})
@Entity
@Table(name = "CBGL_USER")
public class User implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "CBGL_USER_SEQ")
    @SequenceGenerator(name = "CBGL_USER_SEQ", initialValue = 1000, allocationSize = 1)
    private Long id;
    @Column(name = "USERNAME", nullable = false)
    private String username;
    @Column(name = "PASSWORD")
    private String password;
    @Column(name = "FIRST_NAME")
    private String firstName;
    @Column(name = "LAST_NAME")
    private String lastName;
    @Column(name = "EMAIL")
    private String email;
    @Column(name = "EMPLOYEE_NUMBER")
    private String employeeNumber;
    @Column(name = "ENABLE")
    private boolean enable;
    @Column(name = "DESCRIPTION")
    private String description;
    @Column(name = "IS_TEMPORARY")
    private boolean isTemporary;
    @Column(name = "PASSWORD_EXPIRY_DATE")
    private LocalDateTime passwordExpiryDate;

    public LocalDateTime getCreatedOn() {
        return createdOn;
    }

    public void setCreatedOn(LocalDateTime createdOn) {
        this.createdOn = createdOn;
    }

    @Column(name = "CREATED_ON")
    private LocalDateTime createdOn;

    @ManyToMany
    @JoinTable(
            name = "cbgl_User_Role",
            joinColumns = @JoinColumn(name = "user_Id"),
            inverseJoinColumns = @JoinColumn(name = "role_Id")
    )
    private Set<Role> roles;


    public User() {
    }

    public User(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
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

    public String getEmployeeNumber() {
        return employeeNumber;
    }

    public void setEmployeeNumber(String employeeNumber) {
        this.employeeNumber = employeeNumber;
    }

    public boolean isEnable() {
        return enable;
    }

    public void setEnable(boolean enable) {
        this.enable = enable;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    public boolean isTemporary() {
        return isTemporary;
    }

    public void setTemporary(boolean temporary) {
        isTemporary = temporary;
    }

    public LocalDateTime getPasswordExpiryDate() {
        return passwordExpiryDate;
    }

    public void setPasswordExpiryDate(LocalDateTime passwordExpiryDate) {
        this.passwordExpiryDate = passwordExpiryDate;
    }
}