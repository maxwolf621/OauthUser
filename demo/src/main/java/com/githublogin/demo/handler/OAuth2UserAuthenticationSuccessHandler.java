package com.githublogin.demo.handler;

import java.io.IOException;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Optional;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


import com.githublogin.demo.config.OAuth2Properties;
import com.githublogin.demo.exceptions.BadRequestException;
import com.githublogin.demo.oauth2userinfo.OAuth2UserInfo;
import com.githublogin.demo.repository.CustomOAuth2AuthorizationRequestRepository;
import com.githublogin.demo.security.JwtProvider;
import com.githublogin.demo.security.OAuth2UserPrincipal;
import com.githublogin.demo.service.OAuth2Service;
import com.githublogin.demo.utility.CookieUtils;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.social.github.api.impl.GitHubTemplate;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.web.util.UriComponentsBuilder;

import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import static com.githublogin.demo.repository.CustomOAuth2AuthorizationRequestRepository.REDIRECT_URI_COOKIE;

// SimpleUrlAuthenticationSuccessHandler
// https://github.com/spring-projects/spring-security/blob/main/web/src/main/java/org/springframework/security/web/authentication/SimpleUrlAuthenticationSuccessHandler.java

// RestTemplate Example
// https://spring.io/guides/gs/consuming-rest/
// https://howtodoinjava.com/spring-boot2/resttemplate/spring-restful-client-resttemplate-example/

/** Access APi resource
 * https://spring.io/blog/2018/03/06/using-spring-security-5-to-integrate-with-oauth-2-secured-services-such-as-facebook-and-github
 * Authentication object kept in the security context is actually an OAuth2AuthenticationToken which, 
   along with help from OAuth2AuthorizedClientService can avail us 
   with an access token for making requests against the service’s API.
 */
// 
 /* create a jwt token uri to activate  */
@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2UserAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler{

    private final CustomOAuth2AuthorizationRequestRepository customOAuth2AuthorizationRequestRepository;
    private final JwtProvider jwtProvider; 
    private final OAuth2Properties oAuth2Properties;
    private final OAuth2Service oAuth2Service;
    private final OAuth2AuthorizedClientService authorizedClientService;

    @Value("${github.resource.userInfoUri}")
    private String userInfoUri; 
    private static final String GITHUB = "Github";

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String targetUrl = determineTargetUrl(request, response, authentication);
        
        log.info("--------------- Success Handler ---------------");
        if (response.isCommitted()) {
            logger.debug("Client Already Received. Unable to redirect to " + targetUrl);
            return;
        }

        // Oauth2UserPrincipal object authenticated from CustomOauth2UserPrinciaplService
        OAuth2UserPrincipal userPrincipal = (OAuth2UserPrincipal) authentication.getPrincipal();
        OAuth2UserInfo userInfo = userPrincipal.getUserInfo();
        String email =  userInfo.getEmail();
        log.info("   '-------Get Mail: " + email);
        if(userInfo.getAuthProvider().toString().equalsIgnoreCase(GITHUB)){
            log.info("      '---- fetch github private mail");
            OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
            log.info("          '____oauthToken: " + oauthToken.getName());
            OAuth2AuthorizedClient authorizedClient = 
                this.authorizedClientService.loadAuthorizedClient("github", oauthToken.getName());
            log.info("          '___authorizedClient: " + authorizedClient.getPrincipalName());
            String token = authorizedClient.getAccessToken().getTokenValue();
            log.info("          '____TOKEN: " + token);
            GitHubTemplate github = new GitHubTemplate(token);
            LinkedHashMap<String, Object>[] emails = github.getRestTemplate().getForObject(userInfoUri + "/emails", LinkedHashMap[].class);
            email = (String) emails[0].get("email");
            log.info("          '____Private Email: " + email );
        }

        Assert.notNull(email, "Email cant not be null");
        oAuth2Service.processOauth2User(userInfo, email);
    
        clearAuthenticationAttributes(request, response);

        
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }


    /**
     * Form A redirect Uri with jwt queryParm
     */
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        log.info("  '--- determineTargetUrl ");
        Optional<String> redirectUri = CookieUtils.getCookie(request, REDIRECT_URI_COOKIE).map(Cookie::getValue);

        if(redirectUri.isPresent() && !isAuthorizedRedirectUri(redirectUri.get())) {
            throw new BadRequestException("Sorry! We've got an Unauthorized Redirect URI and can't proceed with the authentication");
        }
        
        String targetUrl = redirectUri.orElse(getDefaultTargetUrl());
        String token = jwtProvider.TokenBuilderByOauth2User(authentication);
        return UriComponentsBuilder.fromUriString(targetUrl)
                                   .queryParam("token", token)
                                   .build().toUriString();
    }

    // delete related data taht stored in the session 
    protected void clearAuthenticationAttributes(HttpServletRequest request, HttpServletResponse response) {
        super.clearAuthenticationAttributes(request);
        customOAuth2AuthorizationRequestRepository.removeAuthorizationRequestCookies(request, response);
    }

    /**
     * Compare uri with registerd ones in properties
     */
    private boolean isAuthorizedRedirectUri(String redirectUri) {
        log.info(" '--- isAuthorizedRedirecctUri Method");
        /**
        public static URI create(String str) {
            try {
                    return new URI(str);
                } catch (URISyntaxException x) {
            throw new IllegalArgumentException(x.getMessage(), x);
            }
        }       
        */
        log.info("      '____Redirect uri that provided by Client" + redirectUri);
        URI clientRedirectUri = URI.create(redirectUri);
        
        // Check if client login via mobile or computer
        return oAuth2Properties.getAuthorizedRedirectUris()
                               .stream()
                               .anyMatch(authorizedRedirectUri -> {
                                    log.info("      '___ Check if ClientRedirectUrl is legit");
                                    URI authorizedURI = URI.create(authorizedRedirectUri);
                                    if(authorizedURI.getHost().equalsIgnoreCase(clientRedirectUri.getHost())
                                            && authorizedURI.getPort() == clientRedirectUri.getPort()) {
                                        return true;
                                    }
                                return false;
                });
    }
}
