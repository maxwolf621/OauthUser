package com.githublogin.demo.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
//import org.springframework.context.annotation.Configuration;

import lombok.Data;
import java.util.List;

@ConfigurationProperties(prefix = "app")
@Data
public class OAuth2Properties {
    private List<String> authorizedRedirectUris;
}
