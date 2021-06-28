package com.githublogin.demo.security;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.time.Instant;
import static java.util.Date.from;
import java.sql.Date;

import javax.annotation.PostConstruct;

import org.springframework.security.core.userdetails.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
//import static io.jsonwebtoken.Jwts.parser;
//import io.jsonwebtoken.Claims;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;

// Ref https://www.javainuse.com/webseries/spring-security-jwt/chap7

@Slf4j
@Service
public class JwtProvider {
    private KeyStore keyStore;
    private String alias = "/pttClone.jks";
    
    @Value("${jwt.secret}")
    private String secretKey;
    @Value("${jwt.expiration.time}")
    private Long jwtExpirationInMillis;

    @PostConstruct
    public void init(){
            log.warn("**************initialize the keystore******************");
            try {
                keyStore = KeyStore.getInstance("JKS");
                log.info("** get JKS keyStore");
            } catch (KeyStoreException e) {
                e.printStackTrace();
            }
            InputStream resourceAsStream = getClass().getResourceAsStream(alias);
            try {
                keyStore.load(resourceAsStream, getSecretKey().toCharArray());
                log.warn("**************loading A key store******************");
            } catch (NoSuchAlgorithmException | CertificateException | java.io.IOException e) {
                log.error("Exceptions while loading");
            }
    }
    
    public String TokenBuilderByUser(Authentication authentication){
        log.info("** Generate the Token By A Authentication User");
        // userdetails.User
        User principal = (User) authentication.getPrincipal();
        return Jwts.builder()
                .setSubject(principal.getUsername())
                .setIssuedAt(from(Instant.now()))
                .signWith(getPrivateKey())
                .setExpiration(Date.from(Instant.now().plusMillis(getJwtExpirationInMillis())))
                .compact();
    }       
    public String TokenBuilderByUserName(String username){ 
        log.info("Generate the Token By user's name");
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(from(Instant.now()))
                .signWith(getPrivateKey())
                .setExpiration(Date.from(Instant.now().plusMillis(getJwtExpirationInMillis())))
                .compact();
    }

    private PrivateKey getPrivateKey(){
        try {
            PrivateKey key = (PrivateKey) keyStore.getKey("pttClone", getSecretKey().toCharArray());
            log.info("** get Pivate Key successfully" + key.toString() );
            return key;
        } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            log.info("** Failed to fetch A private Key");
            throw new RuntimeException("Error");
        }
    }

    private PublicKey getPublicKey() throws KeyStoreException{
        log.info("fetch the public key from Certification");
        return keyStore.getCertificate("pttClone").getPublicKey();
    }

    // check the vlidate of the Token used by filter 
    public boolean parserToken(String token){
        log.info("check/parse the validate of the Token");
        try {
            Jwts.parser()
            // check public key correspond to certifiate
            .setSigningKey(getPublicKey())
            // check the token from the request payload
            .parseClaimsJws(token);
            log.info("** The Token is valid");
            return true;
        } catch (SignatureException | ExpiredJwtException | UnsupportedJwtException | MalformedJwtException
                | IllegalArgumentException | KeyStoreException e) {
            e.printStackTrace();
            log.info("** The Token is unvalid");
            return false;
        }
        
    }

    public String getUserNameFromToken(String Token){
            log.info("Fetch the user name from JWT");
            try {
                return Jwts.parser()
                        .setSigningKey(getPublicKey())
                        .parseClaimsJws(Token)
                        .getBody()
                        .getSubject();
            } catch (SignatureException | ExpiredJwtException | UnsupportedJwtException | MalformedJwtException
                    | IllegalArgumentException | KeyStoreException e) {
                e.printStackTrace();
                return null;
            }
    }

    public Long getJwtExpirationInMillis(){
        return jwtExpirationInMillis;
    }
    public String getSecretKey(){
        return secretKey;
    }
}
