package com.zaroyan.springsecurityoauth2exv3.entity;

import jakarta.persistence.*;
import lombok.Data;

/**
 * @author Zaroyan
 */
@Entity
@Table(name="user_entity")
@Data
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;

    private String email;

    @Column(name = "role")
    @Enumerated(EnumType.STRING)
    private UserRole role;

    @Column(name = "source")
    @Enumerated(EnumType.STRING)
    private RegistrationSource source;
}
