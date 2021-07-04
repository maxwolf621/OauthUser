package com.githublogin.demo.customtemplate;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Repository;
import org.springframework.web.client.RestTemplate;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.experimental.UtilityClass;

//SetUp custom ClientId, scope for this application
//  '----> https://stackoverflow.com/questions/27864295/how-to-use-oauth2resttemplate


// Rest Texample example : 
//    '--> https://howtodoinjava.com/spring-boot2/resttemplate/spring-restful-client-resttemplate-example/
//    '-->https://stackoverflow.com/questions/42365266/call-another-rest-api-from-my-server-in-spring-boot

@Repository
public class FetchGithubEmail {

    @Value("${github.fetch.usermails.url}")
    private String uri;

    public String getEmail()
    {  
        RestTemplate restTemplate = new RestTemplate();
    
        String result = restTemplate.getForObject(uri, String.class);
        System.out.println(result);

        return "true";
    }
}
