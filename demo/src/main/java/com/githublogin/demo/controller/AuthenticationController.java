package com.githublogin.demo.controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import javax.validation.Valid;

import com.githublogin.demo.dto.LoginRequest;
import com.githublogin.demo.dto.RefreshTokenRequest;
import com.githublogin.demo.dto.RefreshTokenResponse;
import com.githublogin.demo.dto.RegisterRequest;
import com.githublogin.demo.service.AuthenticationService;
//import com.pttbackend.pttclone.service.RefreshTokenService;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;


/* Controller for Authentication such as
 * login
 * register
 *  ...
 */

@AllArgsConstructor
@RestController
@RequestMapping("/api/auth")
@Slf4j
public class AuthenticationController {

    private final AuthenticationService authService;

    @PostMapping(value="/signup")
    public ResponseEntity<String> signup(@RequestBody RegisterRequest req) {
        authService.signup(req);
        return new ResponseEntity<>("signing up success",HttpStatus.OK);
    }

    // To verify Token for new User 
    // http://localhost:8080/api/auth/accountVerification/{token}
    @GetMapping(value="/accountVerification/{token}")
    public ResponseEntity<String> tokenactivate(@PathVariable String token){
        authService.verifyToken(token);
        return new ResponseEntity<>("Token is Legit",HttpStatus.OK);
    }

    @PostMapping("/login")
    public RefreshTokenResponse login(@RequestBody LoginRequest loginRequest) {
        log.info("** doing login " + loginRequest.toString());
        return authService.login(loginRequest);
    }

    @PostMapping("/refresh/token")
    public RefreshTokenResponse refreshTokens(@Valid @RequestBody RefreshTokenRequest refreshTokenRequest) {
        return authService.refreshToken(refreshTokenRequest);
    }
}
