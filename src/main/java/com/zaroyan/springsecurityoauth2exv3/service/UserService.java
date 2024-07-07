package com.zaroyan.springsecurityoauth2exv3.service;


import com.zaroyan.springsecurityoauth2exv3.entity.UserEntity;
import com.zaroyan.springsecurityoauth2exv3.repository.UserEntityRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * @author Zaroyan
 */

@Service
@Slf4j
public class UserService {

    private final UserEntityRepository userEntityRepository;

    public UserService(UserEntityRepository userEntityRepository) {
        this.userEntityRepository = userEntityRepository;
    }

    public Optional<UserEntity> findByEmail(String email) {
        return userEntityRepository.findByEmail(email);
    }

    public void save(UserEntity user) {
        userEntityRepository.save(user);
        log.info("Пользователь с email {} сохранен в базе данных", user.getEmail());

    }
}
