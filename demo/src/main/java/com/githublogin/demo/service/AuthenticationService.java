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
        log.info("---SingUp Process");
        User newUser = User.builder()
                           .username(req.getUsername())
                           .password(encodePassword(req.getPassword()))
                           .mail(req.getMail())
                           .legit(false)
                           .authProvider(AuthProviderType.LOCAL)
                           .createdDate(Instant.now())
                           .build();
        /*
        User newUser = new User();
        user.setUsername(req.getUsername());
        user.setPassword(encodePassword(req.getPassword()));
        user.setMail(req.getMail());
        user.setLegit(false); // The register haven't get VERTICATIONTOKEN
        user.setAuthProvider(AuthProviderType.LOCAL);
        user.setCreatedDate(Instant.now());
        */

        userRepo.save(newUser); // Save the user to database
        log.info("  '__ Save a new user succesfully");
        String token = generateToken(newUser); 

        /**
         * Send mail to user to activate token
         
        String body = ("click the URL To activate Your Account : " + GoTokenPage.url() + token); 
        String subject = "Activate Your Account";
        String recipient = newUser.getMail();
        */
        NotificationMail ActivateMail = NotificationMail.builder()
                                                        .subject("Activate Your Account")
                                                        .body("click the URL To activate Your Account : " + GoTokenPage.url() + token)
                                                        .recipient(newUser.getMail())
                                                        .build();
        log.info("  '--- SendMailService sendTokenMail(ActivateMail)");
        sendmailService.SendTokenMail(ActivateMail);
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
            // This token will reference to the specific User
            verificationtokonRepo.save(token);        
            return newToken;
    }

    /** 
     * this will be called once the register access the validating token page
     */
     public void verifyToken(String token){
        VerificationToken verificationtoken = 
            verificationtokonRepo.findByToken(token).orElseThrow(() -> new RuntimeException("Invalid Token"));
        log.info("  '--- " + verificationtoken.getUser().getUsername());
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
        log.info("       '--- Saving A Legitimate User Successfully");
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
        log.info("---login process");
        Authentication authenticate = 
                    authenticationManager.authenticate(
                            new UsernamePasswordAuthenticationToken(
                                        loginRequest.getUsername(),loginRequest.getPassword()
                            ));
        
        SecurityContextHolder.getContext().setAuthentication(authenticate);

        // Generate jwt 
        String token = jwtprovider.TokenBuilderByUser(authenticate);
        return RefreshTokenResponse.builder()
                .Token(token)
                .refreshToken(refreshTokenService.generateRefreshToken().getToken())
                .expiresAt(Instant.now())
                //.expiresAt(Instant.now().plusMillis(jwtprovider.getJwtExpirationInMillis()))
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
