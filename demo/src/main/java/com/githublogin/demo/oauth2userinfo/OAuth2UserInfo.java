package com.githublogin.demo.oauth2userinfo;

import java.util.Map;

import com.githublogin.demo.model.AuthProviderType;

public abstract class OAuth2UserInfo {
    
    // claims
    protected Map<String, Object> attributes;

    /**
     *consturctor : 
     *  stores the attributes
     */  
    public OAuth2UserInfo( Map<String, Object> attributes) {
        this.attributes = attributes;
    }
    
    // getters 
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    public abstract AuthProviderType getAuthProvider();

    public abstract String getId();

    public abstract String getUsername();

    public abstract String getEmail();

    //public abstract void printString();
    //public abstract String getImageUrl();
}
