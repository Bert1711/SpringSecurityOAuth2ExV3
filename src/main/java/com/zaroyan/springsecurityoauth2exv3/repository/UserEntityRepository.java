package com.zaroyan.springsecurityoauth2exv3.repository;



import com.zaroyan.springsecurityoauth2exv3.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * @author Zaroyan
 */
public interface UserEntityRepository extends JpaRepository<UserEntity, Long> {

    Optional<UserEntity> findByEmail(String email);
}
