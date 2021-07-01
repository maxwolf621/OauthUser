package com.githublogin.demo.oauth2userInfofactory;
import java.util.Map;

import com.githublogin.demo.exceptions.OAuth2UserInfoAuthenticationException;
import com.githublogin.demo.model.AuthProviderType;
import com.githublogin.demo.oauth2userinfo.GitHubUserInfo;
import com.githublogin.demo.oauth2userinfo.GoogleUserInfo;
import com.githublogin.demo.oauth2userinfo.OAuth2UserInfo;

import lombok.extern.slf4j.Slf4j;

/* To create A userInfo for thirdparty application */
@Slf4j
public class OAuth2UserInfoFactory {
    
    public static OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> claims){
        if(registrationId.equalsIgnoreCase(AuthProviderType.GOOGLE.toString())){
            log.info("Login via Google Account");
            log.info("Claims : " + claims.toString());
            return new GoogleUserInfo(claims);
        }
        else if(registrationId.equalsIgnoreCase(AuthProviderType.GITHUB.toString())){
            log.info("Login via Github Account");
            log.info("Claims : " + claims.toString());
            return new GitHubUserInfo(claims);
        }
        else{
            throw new OAuth2UserInfoAuthenticationException("Login with " + registrationId + " is not supported yet.");
        }
    }
}
