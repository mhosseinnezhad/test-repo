package com.modernisc.security.keycloak.users;


import jakarta.persistence.*;
import java.io.Serializable;

@Entity
@Table(name = "CBGL_ROLE")
public class Role implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "CBGL_ROLE_SEQ")
    @SequenceGenerator(name = "CBGL_ROLE_SEQ", initialValue = 1000, allocationSize = 1)
    private Long id;
    @Column(name = "NAME", nullable = false)
    private String name;
    public Role() {}
    public Role(String name) { this.name = name; }
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
}