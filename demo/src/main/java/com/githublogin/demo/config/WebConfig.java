package com.githublogin.demo.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/* ref 
    https://stackoverflow.com/questions/50184663/global-cors-configuration-breaks-when-migrating-to-spring-boot-2-0-x
    https://shubo.io/what-is-cors/
    https://stackoverflow.com/questions/36968963/how-to-configure-cors-in-a-spring-boot-spring-security-application
*/
@Configuration
@EnableWebMvc
public class WebConfig implements WebMvcConfigurer {

    /*
    addCorsMappings example :
        https://spring.io/guides/gs/rest-service-cors/
    */
    @Override
    public void addCorsMappings(CorsRegistry corsRegistry) {
        //final String Origins = "http://localhost:4200";
        corsRegistry.addMapping("/**")
                .allowedOrigins("*")
                .allowedMethods("GET","POST")
                .maxAge(3600L)
                .allowedHeaders("*")
                .exposedHeaders("Authorization")
                .allowCredentials(true);
    }
}