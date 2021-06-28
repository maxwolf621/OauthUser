package com.githublogin.demo.oauth2userinfo;

import java.util.Map;

import com.githublogin.demo.model.AuthProviderType;

public class GoogleUserInfo extends OAuth2UserInfo {

    public GoogleUserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    private final AuthProviderType authProvider = AuthProviderType.GOOGLE;

    @Override
    public AuthProviderType getAuthProvider(){
        return authProvider;
    }

    @Override
    public String getId() {
        return (String) attributes.get("sub");
    }

    @Override
    public String getUsername() {
        return (String) attributes.get("name");
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }
}
