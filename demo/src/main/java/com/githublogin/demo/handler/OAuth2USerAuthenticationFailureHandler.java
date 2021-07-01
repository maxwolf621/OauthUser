package com.githublogin.demo.handler;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.githublogin.demo.repository.CustomOAuth2AuthorizationRequestRepository;
import com.githublogin.demo.utility.CookieUtils;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import static com.githublogin.demo.repository.CustomOAuth2AuthorizationRequestRepository.REDIRECT_URI_COOKIE;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
@AllArgsConstructor
public class OAuth2USerAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler{
    private final CustomOAuth2AuthorizationRequestRepository customOAuth2AuthorizationRequestRepo;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, 
                                        HttpServletResponse response, 
                                        AuthenticationException exception) 
                                        throws IOException, ServletException {
        log.info("------------- Failure Handler -------------");
        String targetUrl = CookieUtils.getCookie(request, REDIRECT_URI_COOKIE)
                                      .map(Cookie::getValue)
                                      .orElse(("/"));

        targetUrl = UriComponentsBuilder.fromUriString(targetUrl)
                                        .queryParam("error", exception.getLocalizedMessage())
                                        .build().toUriString();
                                        
        log.info("______________targetUrl: "+targetUrl.toString());

        // remove cookies in http session
        customOAuth2AuthorizationRequestRepo.removeAuthorizationRequestCookies(request, response);
        
        // redirect to target url
        getRedirectStrategy().sendRedirect(request, response, targetUrl);

    }
}
