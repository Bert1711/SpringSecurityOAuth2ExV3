package com.zaroyan.springsecurityoauth2exv3.controller;


import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Map;

/**
 * @author Zaroyan
 */


@Slf4j
@RestController
public class HomeController {


    @GetMapping("/")
    public ResponseEntity<String> home(Principal principal) {
        String userLink = "<a href=\"/user\">Моя страница пользователя</a>";
        String adminLink = "<a href=\"/admin\">Администраторская страница</a>";
        log.info("Пользователь {} зашел на главную страницу", principal.getName());
        String responseData = "Здравствуйте, " + principal.getName() + "<br>" +
                "Вход для пользователя: " + userLink + "<br>" +
                "Вход для администратора: " + adminLink;
        return ResponseEntity.status(HttpStatus.OK).body(responseData);
    }

    @PreAuthorize("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN')")
    @GetMapping("/user")
    public ResponseEntity<?> user(Principal principal) {
        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) principal;
        Map<String, Object> attributes = oauthToken.getPrincipal().getAttributes();
        String email = (String) attributes.get("email");
        String registrationSource = oauthToken.getAuthorizedClientRegistrationId();
        log.info("Пользователь {} получил доступ к странице пользователя", principal.getName());
        String responseData = "Данные пользователя: <br>" +
                "Имя: " + principal.getName() + "<br>" +
                "Почта: " + email + "<br>" +
                "Ресурс регистрации: " + registrationSource;
        return ResponseEntity.status(HttpStatus.OK).body(responseData);
    }


    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/admin")
    public ResponseEntity<?> admin(Principal principal) {
        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) principal;
        Map<String, Object> attributes = oauthToken.getPrincipal().getAttributes();
        String email = (String) attributes.get("email");
        String registrationSource = oauthToken.getAuthorizedClientRegistrationId();
        String responseData = "Данные администратора: <br>" +
                "Имя: " + principal.getName() + "<br>" +
                "Почта: " + email + "<br>" +
                "Ресурс регистрации: " + registrationSource;
        log.info("Пользователь {} получил доступ к странице администратора", principal.getName());
        return ResponseEntity.status(HttpStatus.OK).body(responseData);
    }
}
