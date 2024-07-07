package com.zaroyan.springsecurityoauth2exv3.config;


import com.zaroyan.springsecurityoauth2exv3.entity.RegistrationSource;
import com.zaroyan.springsecurityoauth2exv3.entity.UserEntity;
import com.zaroyan.springsecurityoauth2exv3.entity.UserRole;
import com.zaroyan.springsecurityoauth2exv3.service.UserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * @author Zaroyan
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2LoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private final UserService userService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws ServletException, IOException {
        OAuth2AuthenticationToken oAuth2AuthenticationToken = (OAuth2AuthenticationToken) authentication;
        log.info("Пользователь успешно аутентифицирован с использованием регистрации: {}", oAuth2AuthenticationToken.getAuthorizedClientRegistrationId());

        if ("google".equals(oAuth2AuthenticationToken.getAuthorizedClientRegistrationId())) {
            DefaultOAuth2User principal = (DefaultOAuth2User) authentication.getPrincipal();
            Map<String, Object> attributes = principal.getAttributes();

            attributes.forEach((key, value) -> log.info(key + ": " + value));

            String email = attributes.getOrDefault("email", "").toString();
            String name = attributes.getOrDefault("name", "").toString();


            log.info(email);
            userService.findByEmail(email).ifPresentOrElse(user -> {
                DefaultOAuth2User newUser = new DefaultOAuth2User(
                        List.of(new SimpleGrantedAuthority(user.getRole().name())),
                        attributes,
                        "name"
                );
                Authentication securityAuth = new OAuth2AuthenticationToken(
                        newUser,
                        List.of(new SimpleGrantedAuthority(user.getRole().name())),
                        oAuth2AuthenticationToken.getAuthorizedClientRegistrationId()
                );
                SecurityContextHolder.getContext().setAuthentication(securityAuth);
            }, () -> {
                UserEntity userEntity = new UserEntity();
                userEntity.setRole(UserRole.ROLE_USER);
                userEntity.setEmail(email);
                userEntity.setName(name);
                userEntity.setSource(RegistrationSource.GOOGLE);
                userService.save(userEntity);

                DefaultOAuth2User newUser = new DefaultOAuth2User(
                        List.of(new SimpleGrantedAuthority(userEntity.getRole().name())),
                        attributes,
                        "name"
                );
                Authentication securityAuth = new OAuth2AuthenticationToken(
                        newUser,
                        List.of(new SimpleGrantedAuthority(userEntity.getRole().name())),
                        oAuth2AuthenticationToken.getAuthorizedClientRegistrationId()
                );
                SecurityContextHolder.getContext().setAuthentication(securityAuth);
            });
        }

        if ("github".equals(oAuth2AuthenticationToken.getAuthorizedClientRegistrationId())) {
            DefaultOAuth2User principal = (DefaultOAuth2User) authentication.getPrincipal();
            Map<String, Object> attributes = principal.getAttributes();

            attributes.forEach((key, value) -> log.info(key + ": " + value));

            String email = attributes.getOrDefault("email", "").toString();
            String name = attributes.getOrDefault("name", "").toString();

            // TODO: email может быть пустым, нужно будет обработать это!!!

            log.info(email);
            userService.findByEmail(email).ifPresentOrElse(user -> {
                DefaultOAuth2User newUser = new DefaultOAuth2User(
                        List.of(new SimpleGrantedAuthority(user.getRole().name())),
                        attributes,
                        "name"
                );
                Authentication securityAuth = new OAuth2AuthenticationToken(
                        newUser,
                        List.of(new SimpleGrantedAuthority(user.getRole().name())),
                        oAuth2AuthenticationToken.getAuthorizedClientRegistrationId()
                );
                SecurityContextHolder.getContext().setAuthentication(securityAuth);
            }, () -> {
                UserEntity userEntity = new UserEntity();
                userEntity.setRole(UserRole.ROLE_USER);
                userEntity.setEmail(email);
                userEntity.setName(name);
                userEntity.setSource(RegistrationSource.GITHUB);
                userService.save(userEntity);

                DefaultOAuth2User newUser = new DefaultOAuth2User(
                        List.of(new SimpleGrantedAuthority(userEntity.getRole().name())),
                        attributes,
                        "name"
                );
                Authentication securityAuth = new OAuth2AuthenticationToken(
                        newUser,
                        List.of(new SimpleGrantedAuthority(userEntity.getRole().name())),
                        oAuth2AuthenticationToken.getAuthorizedClientRegistrationId()
                );
                SecurityContextHolder.getContext().setAuthentication(securityAuth);
            });
        }

        super.onAuthenticationSuccess(request, response, authentication);
    }
}


