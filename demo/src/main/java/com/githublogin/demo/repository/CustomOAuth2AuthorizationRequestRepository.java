package com.githublogin.demo.repository;

import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Repository;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.githublogin.demo.utility.CookieUtils;

/**
 * 
 * Clinet <-> Customoauth2AuthorizatioRepository <-> Authorization Proivder
 */

@Repository
public class CustomOAuth2AuthorizationRequestRepository implements AuthorizationRequestRepository<OAuth2AuthorizationRequest>{
    
    // cookie name
    public static final String AUTHORIZATION_REQUEST_COOKIE_NAME = "oauth2_auth_request";

    // redirect endpoint
    public static final String REDIRECT_URI_COOKIE_NAME = "redirect_uri";

    private static final int cookieExpireSeconds = 180;

    /**
     * Load Authroization Request from Authorization Server (via request's given information)
     * To compare the clientrequest's cookie and Authorization Provider's cookie
     * @Returns the OAuth2AuthorizationRequest (from Servlet) \ 
     * associated to the provided HttpServletRequest (from Client) \
     * or null if not available. 
    */
    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        Assert.notNull(request, "request cannot be null");
        return CookieUtils.getCookie(request, AUTHORIZATION_REQUEST_COOKIE_NAME)
                .map(cookie -> CookieUtils.deserialize(cookie, OAuth2AuthorizationRequest.class))
                .orElse(null);
    }

    /**
     * Persists(To store)
     * the (serialized) OAuth2AuthorizationRequest associating it \ 
     * to the provided HttpServletRequest and/or HttpServletResponse.
     * (To save Authorization Request) in the http server session 
     */
    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request, HttpServletResponse response) {
        Assert.notNull(request, "request cannot be null");
		Assert.notNull(response, "response cannot be null");
        if (authorizationRequest == null) {
            // delete the cookies stores in the http session
            CookieUtils.deleteCookie(request, response, AUTHORIZATION_REQUEST_COOKIE_NAME);
            CookieUtils.deleteCookie(request, response, REDIRECT_URI_COOKIE_NAME);
            return;
        }
        
        // Add cookies provided from Authorization Server to response payload 
        // (store cookies in the http session)
        CookieUtils.addCookie(response, AUTHORIZATION_REQUEST_COOKIE_NAME, CookieUtils.serialize(authorizationRequest), cookieExpireSeconds);
        String redirectUriAfterLogin = request.getParameter(REDIRECT_URI_COOKIE_NAME);
        if (!(redirectUriAfterLogin).isBlank()) {
            CookieUtils.addCookie(response, REDIRECT_URI_COOKIE_NAME, redirectUriAfterLogin, cookieExpireSeconds);
        }
    }

    /** 
    - Used by Oauth2UserLoginAuthenticationfilter 
    - Load the cookies stored in the http session
    - Delete the cookies in the http session 
    */
    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request, HttpServletResponse response) {
        OAuth2AuthorizationRequest originalRequest = this.loadAuthorizationRequest(request);
        this.removeAuthorizationRequestCookies(request, response);
        return originalRequest;
    }

    @Deprecated
	@Override
	public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request) {
		throw new UnsupportedOperationException("Spring Security shouldn't have called the deprecated removeAuthorizationRequest(request)");
	}

    //Remove the cookies in http session 
    public void removeAuthorizationRequestCookies(HttpServletRequest request, HttpServletResponse response){
        CookieUtils.deleteCookie(request, response, AUTHORIZATION_REQUEST_COOKIE_NAME);
        CookieUtils.deleteCookie(request, response, REDIRECT_URI_COOKIE_NAME);
    }
}
