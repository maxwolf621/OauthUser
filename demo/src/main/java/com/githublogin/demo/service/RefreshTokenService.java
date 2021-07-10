package com.githublogin.demo.service;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

import com.githublogin.demo.model.RefreshToken;
import com.githublogin.demo.repository.RefreshTokenRepository;


/**
 * this Service will be used by jwtProvider, AuthenticationService
 */

@Service
@AllArgsConstructor
@Transactional
@Slf4j
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepo;

    public RefreshToken generateRefreshToken() {
        /** 
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setCreatedDate(Instant.now());
        */

        RefreshToken refreshToken = RefreshToken.builder()
                                                .token(UUID.randomUUID().toString())
                                                .createdDate(Instant.now())
                                                .build();
        return refreshTokenRepo.save(refreshToken);
    }

    void validateRefreshToken(String token) {
        RefreshToken refreshToken= refreshTokenRepo.findByToken(token).orElseThrow(
            () -> new RuntimeException("Invalid refresh Token")
        );
        log.info("RefreshToken " + refreshToken.getToken() + "is validate");
    }

    public void deleteRefreshToken(String token) {
        refreshTokenRepo.deleteByToken(token);
        log.info("The Token is deleted");
    }
}

