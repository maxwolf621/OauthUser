package com.githublogin.demo.service;

import org.springframework.stereotype.Service;

import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import static java.util.Collections.singletonList;

/**
 * Map the userinfo from third party application's resource
 */
import com.githublogin.demo.oauth2userInfofactory.OAuth2UserInfoFactory;
import com.githublogin.demo.oauth2userinfo.OAuth2UserInfo;
import com.githublogin.demo.security.OAuth2UserPrincipal;

/**
 -------------- REFERENCE CODE --------------
 - Code of DefaultOAuth2UserService
   https://github.com/spring-projects/spring-security/blob/main/oauth2/oauth2-client/src/main/java/org/springframework/security/oauth2/client/userinfo/DefaultOAuth2UserService.java
 - Example of DefaultOAuth2User
   https://www.codota.com/code/java/methods/org.springframework.security.oauth2.core.user.DefaultOAuth2User/%3Cinit%3E
*/

/**
 * CustomOauth2UserServiceTest will return a authentication user from third party application
 * */
@Service
@AllArgsConstructor
@Slf4j
public class CustomOAuth2UserPrincipalService extends DefaultOAuth2UserService {

    // oauthe2userRequest contains clientregistration,token, additional parameter
    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {
        log.info("------------- CustomOauth2User Service -------------");
        
        OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);
        log.info(" '___oauth2User: " +  oAuth2User);
        String authProvider = oAuth2UserRequest.getClientRegistration().getRegistrationId();
        log.info(" '___authProvider: " + authProvider);
        OAuth2UserInfo userInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(authProvider, oAuth2User.getAttributes());
        
        try{      
            /**
             --------------------- To Return A Authenticated Authentication ---------------------
             ------  DefaultOAuth2User(authorities, userAttributes, userNameAttributeName) ------
             
             * userNameAttributeName 
                    '-> The name of the attribute returned in the UserInfo Response 
                        that references the Name or Identifier of the end-user.
             * userAttributes
                    '-> user principal 
             * Oauth2UserInfo
                    '-> userinfo from third party application (name, emails, ... )
            */
            log.info(" '____RETURN OAuth2UserPrincipal for the Authentication");
            return new OAuth2UserPrincipal(singletonList(new SimpleGrantedAuthority("USER")), 
                                                                    oAuth2User.getAttributes(), 
                                                                    "name",
                                                                    userInfo);
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            // Throwing an instance of AuthenticationException will trigger the OAuth2AuthenticationFailureHandler
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    } 

}
