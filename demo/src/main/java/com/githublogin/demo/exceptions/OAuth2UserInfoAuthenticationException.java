package com.githublogin.demo.exceptions;

import org.springframework.security.core.AuthenticationException;

public class OAuth2UserInfoAuthenticationException extends AuthenticationException {
    public OAuth2UserInfoAuthenticationException(String msg, Throwable t) {
        super(msg, t);
    }
    public OAuth2UserInfoAuthenticationException(String msg) {
        super(msg);
    }
}
