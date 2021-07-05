package com.githublogin.demo.service;

import com.githublogin.demo.model.User;
import com.githublogin.demo.oauth2userinfo.OAuth2UserInfo;
import com.githublogin.demo.repository.UserRepository;

import org.springframework.stereotype.Service;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;

/**
 * UserService
             '--> for Oauth2 User to register or update the account for this application
 */

@Service
@AllArgsConstructor
@Slf4j
public class OAuth2Service {
    private UserRepository userRepo;

    public User register(OAuth2UserInfo userInfo){
        log.info("  '--- Register a new Member");
        User newMember = User.builder()
                             .mail(userInfo.getEmail())
                             .authProvider(userInfo.getAuthProvider())
                             .username(userInfo.getUsername())
                             .createdDate(Instant.now())
                             .legit(true)
                             .build();
        return userRepo.save(newMember);
    }

    public User update(User existingUser, OAuth2UserInfo userInfo){
        log.info("  '--- Update The Member Data From the Third Party Application");
        existingUser.setUsername(userInfo.getUsername());
        return userRepo.save(existingUser);
    }

    public void processOauth2User(OAuth2UserInfo userInfo, String email){
        log.info("      '--- Process Oauth2 User");
        User thisUser = userRepo.findByMail(email)
                                .map(user-> update(user, userInfo))
                                .orElseGet(()->register(userInfo));
        log.info("          '--- Show Member Name:"+thisUser.getUsername());
    }
}
