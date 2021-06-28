package com.githublogin.demo.oauth2userinfo;

import java.util.Map;

import com.githublogin.demo.model.AuthProviderType;

public class GitHubUserInfo extends OAuth2UserInfo {
    public GitHubUserInfo(Map<String, Object> claims){
        super(claims);
    }

    private final AuthProviderType authProvider = AuthProviderType.GITHUB;

    @Override
    public AuthProviderType getAuthProvider(){
        return authProvider;
    } 

    @Override
    public String getId() {
        return ((Integer) attributes.get("id")).toString();
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
