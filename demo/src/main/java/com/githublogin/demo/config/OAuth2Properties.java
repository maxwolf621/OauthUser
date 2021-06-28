package com.githublogin.demo.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@ConfigurationProperties(prefix = "app")
public class OAuth2Properties {
    
    private List<String> authorizedRedirectUris;

    public List<String> getAuthorizedRedirectUris(){
        return authorizedRedirectUris;
    }
    
    
}
