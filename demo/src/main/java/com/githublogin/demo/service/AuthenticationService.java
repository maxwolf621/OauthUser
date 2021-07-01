package com.githublogin.demo.service;

import java.time.Instant;
//import java.util.Optional;
import java.util.UUID;

import com.githublogin.demo.dto.LoginRequest;
//import com.githublogin.demo.dto.LoginResponse;
import com.githublogin.demo.dto.RefreshTokenRequest;
import com.githublogin.demo.dto.RefreshTokenResponse;
import com.githublogin.demo.dto.RegisterRequest;
import com.githublogin.demo.model.AuthProviderType;
import com.githublogin.demo.model.NotificationMail;
import com.githublogin.demo.model.User;
import com.githublogin.demo.model.VerificationToken;
import com.githublogin.demo.repository.UserRepository;
import com.githublogin.demo.repository.VerificationTokenRepository;
import com.githublogin.demo.security.JwtProvider;
import com.githublogin.demo.utility.GoTokenPage;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@AllArgsConstructor
@Slf4j
@Transactional
public class AuthenticationService {

    private final UserRepository userRepo;
    private final PasswordEncoder passwordEncoder;
    private final VerificationTokenRepository verificationtokonRepo;
    private final SendMailService sendmailService;
    private final RefreshTokenService refreshTokenService;
    private final AuthenticationManager authenticationManager;
    private final JwtProvider jwtprovider;

    // 1. create a user and save it to database
    // 2. generate the token 
    // 3. send mail to user to activate the account
    public void signup(RegisterRequest req){
        User user = new User();
        user.setUsername(req.getUsername());
        user.setPassword(encodePassword(req.getPassword()));
        user.setMail(req.getMail());
        user.setCreatedDate(Instant.now());
        
        user.setLegit(false); // The register haven't get VERTICATIONTOKEN
        user.setAuthProvider(AuthProviderType.LOCAL);
        
        userRepo.save(user); // Save the user to database
        log.info("save a new user succesfully");
        //log.info(user.getMail() + " " + user.getPassword() +  " " + user.getUserName() );
        
        
        String token = generateToken(user); // Create a token via user
        log.info("Create A Token For A new User" + token);

        /**
         * Send mail to user to activate token
         */
        String body = ("click the URL To activate Your Account \n" + GoTokenPage.url() + token); 
        String subject = "PttClone Activate Your Account";
        String recipient = user.getMail();
        NotificationMail userMail = new NotificationMail(subject, recipient, body);  // Mail Content
        sendmailService.SendTokenMail(userMail);
    }
    
    /**
     *  Encrypt the password of the user
     */
    private String encodePassword(String password) {
        return passwordEncoder.encode(password);
    }

    /** 
     * Used by singup method to verficate the user account
     */
     public String generateToken(User user){
            VerificationToken token = new VerificationToken();
            String newToken = UUID.randomUUID().toString();
            token.setToken(newToken);
            token.setUser(user);
            verificationtokonRepo.save(token);        
            return newToken;
    }

    /** 
     * this will be called once the register access the validating token page
     */
     public void verifyToken(String token){
        VerificationToken verificationtoken = 
            verificationtokonRepo.findByToken(token).orElseThrow(() -> new RuntimeException("Invalid Token"));
        log.info(verificationtoken.getUser().getUsername());
        setUserValid(verificationtoken);
    }
    /**
     * Used by verifyToken method
     */
    private void setUserValid(VerificationToken verificationtoken){
        String username = verificationtoken.getUser().getUsername();
        User user = userRepo.findByUsername(username).orElseThrow(() -> new RuntimeException ("User not found with name - " + username));;
        user.setLegit(true);
        userRepo.save(user);
    }


    /*
    public LoginResponse login(LoginRequest req){
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(req.getUsername(),
                                                        req.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(auth);
        String authenticationToken = jwtprovider.TokenBuilderByUser(auth);
        return new LoginResponse(authenticationToken, req.getUsername());
    }
    */

    
    /**
     * Use jwt to login
     */
    public RefreshTokenResponse login(LoginRequest loginRequest) {
        log.info("--------------Login Service--------------------");
        Authentication authenticate = 
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(),loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authenticate);

        // Generate jwt 
        String token = jwtprovider.TokenBuilderByUser(authenticate);
        return RefreshTokenResponse.builder()
                .Token(token)
                .refreshToken(refreshTokenService.generateRefreshToken().getToken())
                .expiresAt(Instant.now().plusMillis(jwtprovider.getJwtExpirationInMillis()))
                .username(loginRequest.getUsername())
                .build();
    }

    /**
     * If Token is expire then refresh the token
     */
    public RefreshTokenResponse refreshToken(RefreshTokenRequest refreshTokenRequest) {
        refreshTokenService.validateRefreshToken(refreshTokenRequest.getRefreshToken());
        String token = jwtprovider.TokenBuilderByUserName(refreshTokenRequest.getUsername());
        return RefreshTokenResponse.builder()
                .Token(token)
                .refreshToken(refreshTokenRequest.getRefreshToken())
                .expiresAt(Instant.now().plusMillis(jwtprovider.getJwtExpirationInMillis()))
                .username(refreshTokenRequest.getUsername())
                .build();
    }

    /**
     * SecurityContextHolder -> context -> authentication to ge current userdetail (principal)
     */
    @Transactional(readOnly = true)
    public User getCurrentUser(){
        org.springframework.security.core.userdetails.User principal =
        (org.springframework.security.core.userdetails.User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String username = principal.getUsername();
        return userRepo.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("The user your serach" + username +"doesn't exist"));
    }

    /**
     * Check via AnomumousAuthenticationToken and .isAuthenticated()
     */
    public boolean isUserLoggedIn() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return !(authentication instanceof AnonymousAuthenticationToken) && authentication.isAuthenticated();
    }
    
}
