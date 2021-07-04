package com.githublogin.demo.handler;

import java.io.IOException;
import java.net.URI;
import java.util.Optional;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.githublogin.demo.config.OAuth2Properties;
import com.githublogin.demo.exceptions.BadRequestException;
import com.githublogin.demo.repository.CustomOAuth2AuthorizationRequestRepository;
import com.githublogin.demo.security.JwtProvider;
import com.githublogin.demo.utility.CookieUtils;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import static com.githublogin.demo.repository.CustomOAuth2AuthorizationRequestRepository.REDIRECT_URI_COOKIE;

// SimpleUrlAuthenticationSuccessHandler
// https://github.com/spring-projects/spring-security/blob/main/web/src/main/java/org/springframework/security/web/authentication/SimpleUrlAuthenticationSuccessHandler.java

/* create a jwt token uri to activate  */
@Component
@AllArgsConstructor
@Slf4j
public class OAuth2UserAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler{

    private final CustomOAuth2AuthorizationRequestRepository customOAuth2AuthorizationRequestRepository;
    private final JwtProvider jwtProvider; 
    private final OAuth2Properties oAuth2Properties;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String targetUrl = determineTargetUrl(request, response, authentication);
        log.info("--- Success Handler");
        if (response.isCommitted()) {
            logger.debug("Client Already Received. Unable to redirect to " + targetUrl);
            return;
        }

        clearAuthenticationAttributes(request, response);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        Optional<String> redirectUri = CookieUtils.getCookie(request, REDIRECT_URI_COOKIE)
                .map(Cookie::getValue);

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
    private boolean isAuthorizedRedirectUri(String uri) {
        /**
        public static URI create(String str) {
            try {
                    return new URI(str);
                } catch (URISyntaxException x) {
            throw new IllegalArgumentException(x.getMessage(), x);
            }
        }       
        */
        log.info("client uri" + uri);
        URI clientRedirectUri = URI.create(uri);
        
        // Check if client login via mobile or computer
        return oAuth2Properties.getAuthorizedRedirectUris()
                .stream()
                .anyMatch(authorizedRedirectUri -> {
                    log.info("authorized uri" + authorizedRedirectUri);
                    URI authorizedURI = URI.create(authorizedRedirectUri);
                    if(authorizedURI.getHost().equalsIgnoreCase(clientRedirectUri.getHost())
                            && authorizedURI.getPort() == clientRedirectUri.getPort()) {
                        return true;
                    }
                    return false;
                });
    }
}
