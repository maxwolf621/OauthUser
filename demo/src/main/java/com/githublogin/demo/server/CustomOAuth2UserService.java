package com.githublogin.demo.server;

import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import com.githublogin.demo.exceptions.OAuth2UserInfoAuthenticationException;
import com.githublogin.demo.model.User;
import com.githublogin.demo.oauth2userInfofactory.OAuth2UserInfoFactory;
import com.githublogin.demo.oauth2userinfo.OAuth2UserInfo;
import com.githublogin.demo.repository.UserRepository;

import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;
import static java.util.Collections.singletonList;

/**
 * Code of DefaultOAuth2UserService
 * https://github.com/spring-projects/spring-security/blob/main/oauth2/oauth2-client/src/main/java/org/springframework/security/oauth2/client/userinfo/DefaultOAuth2UserService.java
 * Example of DefaultOAuth2User
 * https://www.codota.com/code/java/methods/org.springframework.security.oauth2.core.user.DefaultOAuth2User/%3Cinit%3E
*/


/**
 *  1. Log In/Sing Up via third-party applcation
 *  2. Update User details in Local 
 *  3. Return the authenticated user 
 * */
@Service
@AllArgsConstructor
@Slf4j
public class CustomOAuth2UserService extends DefaultOAuth2UserService{
    private final UserRepository userRepo;
    
    // oauthe2userRequest contains clientregistration,token, additional parameter
    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {
        log.info("------------- CustomOauth2User Service -------------");
        //  return DefaultOAuth2User(authorities, userAttributes, userNameAttributeName)
        //  userNameAttributeName : 
        //     '-> The name of the attribute returned in the UserInfo Response that references the Name or Identifier of the end-user.
        //  userAttributes : user principal 
        OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);
        log.info("___oauth2User: " +  oAuth2User);

        /**
        Name: [68631186], 
        Granted Authorities: [[ROLE_USER, SCOPE_user:email]], 
        User Attributes: [{
         login=maxwolf621, 
         id=68631186,
         node_id=MDQ6VXNlcjY4NjMxMTg2, 
         avatar_url=https://avatars.githubusercontent.com/u/68631186?v=4, 
         gravatar_id=, url=https://api.github.com/users/maxwolf621, 
         html_url=https://github.com/maxwolf621, 
         followers_url=https://api.github.com/users/maxwolf621/followers, 
         following_url=https://api.github.com/users/maxwolf621/following{/other_user}, 
         gists_url=https://api.github.com/users/maxwolf621/gists{/gist_id}, 
         starred_url=https://api.github.com/users/maxwolf621/starred{/owner}{/repo},
         subscriptions_url=https://api.github.com/users/maxwolf621/subscriptions, 
         organizations_url=https://api.github.com/users/maxwolf621/orgs, 
         repos_url=https://api.github.com/users/maxwolf621/repos, 
         events_url=https://api.github.com/users/maxwolf621/events{/privacy}, 
         received_events_url=https://api.github.com/users/maxwolf621/received_events, 
         type=User, site_admin=false, name=maxwolf621, 
         company=null, blog=, location=null, 
         email=null, hireable=null, bio=null, 
         twitter_username=null, 
         public_repos=13, public_gists=0, followers=0, 
         following=0, created_at=2020-07-22T05:37:14Z, 
         updated_at=2021-06-30T12:48:50Z
        }]
         
         */

        String authProvider = oAuth2UserRequest.getClientRegistration().getRegistrationId();
        log.info("___authProvider: " + authProvider);
        
        
        try{
            /* set up a user */
            processOAuth2User(authProvider, oAuth2User);
            log.info(" '----return DefaultOauth2User");
            return new DefaultOAuth2User(singletonList(new SimpleGrantedAuthority("USER")), 
                                                                    oAuth2User.getAttributes(), 
                                                                    "name");
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            // Throwing an instance of AuthenticationException will trigger the OAuth2AuthenticationFailureHandler
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    } 

    
    /* using email to find the user */
    private void processOAuth2User(String authProvider, OAuth2User oAuth2User){
        log.info(" '--- processOauth2User method ---");
        // mapper a userInfo 
        OAuth2UserInfo userInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(authProvider, oAuth2User.getAttributes());

        log.info(" '--- userInfo Name "+ userInfo.getUsername());
        log.info(" '--- userInfo Emails "+ userInfo.getEmail());
        
        Assert.notNull(userInfo.getEmail(), "Email not null");
        // check if mail is null
        /*if(userInfo.getEmail().isBlank()) {
            log.error(" '--- user has no email");
            throw new OAuth2UserInfoAuthenticationException("Email not found from OAuth2AuthenticationManagerProvider");
        }*/

        log.info(" '--- call findByMail");
        /*  update the local database
            https://stackoverflow.com/questions/53039013/java-9-ifpresentorelse-returning-value/53039364
         */
        User thisUser = userRepo.findByMail(userInfo.getEmail())
                           .map(user-> updateTheMember(user, userInfo))
                           .orElseGet(()->registerAnewMember(userInfo));
        log.info(" '--- Show Member Name:"+thisUser.getUsername());
    }

    private User registerAnewMember(OAuth2UserInfo userInfo){
        log.info(" '--- Register a new Member");
        User newMember = User.builder()
                            .authProvider(userInfo.getAuthProvider())
                            .username(userInfo.getUsername())
                            .createdDate(Instant.now())
                            .legit(true)
                            .build();
        return userRepo.save(newMember);
    }

    private User updateTheMember(User user, OAuth2UserInfo userInfo){
        log.info(" '--- Update The Member");
        user.setUsername(userInfo.getUsername());
        return userRepo.save(user);
    }
}
