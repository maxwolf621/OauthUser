package com.githublogin.demo.controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
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

    @ApiOperation(
        value = "Registration",
        notes = "https://mailtrap.io/signin")
    @ApiResponses(value = 
        {@ApiResponse(code = 500,message = "Duplicate Email")}
    )
    @PostMapping(value="/signup")
    public ResponseEntity<String> signup(@ApiParam(value = "DTO") @RequestBody RegisterRequest req) {
        authService.signup(req);
        log.info("Upon Successful Registration");
        return new ResponseEntity<>("Upon Successful Registration",HttpStatus.OK);
    }

    // To verify Token for new User 
    @ApiOperation(value = "Activate A New User")
    @ApiResponses(
        {@ApiResponse(code = 500, message = "Illegitimate Token")})
    @GetMapping(value="/accountVerification/{token}")
    public ResponseEntity<String> tokenactivate(@PathVariable String token){
        authService.verifyToken(token);
        
        log.info("Legitmate Token");
        return new ResponseEntity<>("Token Legitimate",HttpStatus.OK);
    }

    @ApiOperation(value = "login proccess")
    @PostMapping("/login")
    public RefreshTokenResponse login(@RequestBody LoginRequest loginRequest) {
        log.info(loginRequest.getUsername() + ": Loging In ");
        /**
         * Return legitimate Token to client 
         *      user saves in the session)
         */
        return authService.login(loginRequest);
    }

    @ApiOperation(value = "refreshToken if token expired")
    @PostMapping("/refresh/token")
    public RefreshTokenResponse refreshTokens(@Valid @RequestBody RefreshTokenRequest refreshTokenRequest) {
        log.info("Token is Expired");
        log.info("  '--- Start to Process of Refresh Token");
        /**
         * Return A refresh Token
         */
        return authService.refreshToken(refreshTokenRequest);
    }
}
