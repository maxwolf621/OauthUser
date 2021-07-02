package com.githublogin.demo.config;

import com.githublogin.demo.handler.OAuth2USerAuthenticationFailureHandler;
import com.githublogin.demo.handler.OAuth2UserAuthenticationSuccessHandler;
import com.githublogin.demo.repository.CustomOAuth2AuthorizationRequestRepository;
import com.githublogin.demo.service.CustomOAuth2UserService;

import com.githublogin.demo.filter.JwtAuthenticationFilter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
//import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
//import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
//import org.springframework.http.HttpMethod;


import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@EnableWebSecurity
@AllArgsConstructor
@Slf4j
public class SecurityConfig extends WebSecurityConfigurerAdapter{
    /*
    http://localhost:8080/login/oauth2/code/github?
    error=redirect_uri_mismatch&
    error_description=The+redirect_uri+MUST+match+the+registered+callback+URL+for+this+application.
    &error_uri=https%3A%2F%2Fdocs.github.com%2Fapps%2Fmanaging-oauth-apps%2Ftroubleshooting-authorization-request-errors%2F%23redirect-uri-mismatch&state=MVNKFXPcNoObM666KHOzPyIVI7TTlPPuQa-PnV4EXpY%3D

    https://github.com/login?
    client_id=de5157cd84c0f562b752
    &return_to=%2Flogin%2Foauth%2Fauthorize%3Fclient_id%3Dde5157cd84c0f562b752%26redirect_uri%3Dhttp%253A%252F%252Flocalhost%253A8080%252Foauth2%252Fcallback%252Fgithub%26response_type%3Dcode%26scope%3Dread%253Auser%26state%3DIlywLnN-cvpEKlBYNx_7akqdS-7yW1-Z5LLkTzhuZR0%253D
    
    
    https://github.com/login/oauth/authorize?
    response_type=code&
    client_id=de5157cd84c0f562b752&scope=read:user&
    state=GseX_VxWXBCoAr9KiiSgspS7U_cJ0WWXa3r0ziDMJO4%3D&
    redirect_uri=http://localhost:8080/oauth2/callback/github
    */
    private final CustomOAuth2AuthorizationRequestRepository authorizationRequestRepository;
    private final OAuth2UserAuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    private final OAuth2USerAuthenticationFailureHandler oAuth2USerAuthenticationFailureHandler;
    private final CustomOAuth2UserService userService;


    private final UserDetailsService userdetailsService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;


    @Override
    public void configure(HttpSecurity http) throws Exception{
        http
            .cors()
                .and()
            .csrf()
                .disable()
            .formLogin()
                .disable()
            .httpBasic()
                .disable()
            .authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
            .oauth2Login()
                .authorizationEndpoint()
                    .authorizationRequestRepository(authorizationRequestRepository)
                    .and()
                .redirectionEndpoint()
                    .baseUri("/oauth2/callback/**")
                    .and()
                .userInfoEndpoint()
                    .userService(userService)
                    .and()
                .successHandler(oAuth2AuthenticationSuccessHandler)
                .failureHandler(oAuth2USerAuthenticationFailureHandler);

        log.info("---------Filter For Local Login");
        http.addFilterBefore(jwtAuthenticationFilter,UsernamePasswordAuthenticationFilter.class);
    }


    /**
     * For local login
     */
    @Bean
    public AuthorizationRequestRepository<OAuth2AuthorizationRequest> customAuthorizationRequestRepository() {
	    return new CustomOAuth2AuthorizationRequestRepository();
    }

    /* For Local Authentication*/
    @Bean
    PasswordEncoder passwordEncoder(){
            return new BCryptPasswordEncoder();
    }

    //Generate A Custom AuthenticationProvider
    // and Expose it as a bean (Automatic Injection)
    @Bean(BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    // Configure custom AuthenticationProvider in a AuthenticationManager
    @Autowired
    public void configureCustomProvider(AuthenticationManagerBuilder buildauthenticationprovider) throws Exception{
        buildauthenticationprovider.userDetailsService(userdetailsService).passwordEncoder(passwordEncoder());
    }
}
