[Annotation for bean](https://segmentfault.com/a/1190000021679236)
[shortcome of the field based constructor](https://zhuanlan.zhihu.com/p/337498135)
[EnableGlobalMethodSecurity](https://matthung0807.blogspot.com/2019/09/spring-security-enableglobalmethodsecur.html)
[RolesAllowed and PreAuthorize](https://stackoverflow.com/questions/43961625/rolesallowed-vs-preauthorize-vs-secured)
## Implemenetaions of websecurityconfigurerAdapter
```java

@Condiguration     
@EnableWebSecurity // Set Web Security On
@EnableGlobalMethodSecurity(
        securedEnabled = true, // save as roles allowed
        jsr250Enabled = true,  //roles allowed
        prePostEnabled = true
)
@AllargsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter{
    
    // to get principal (user's details)
    CustomUserDetailsService userDetailsService;

    // Custom filte to be added in http.addbeforefilter(...)
    @Bean
    public CustomFilter customFilter(){
      return new customFilter();
    }

    // build a AuthenticationProvider via AuthenticationManager
    //  we need to setup how this provider to fetch the userdetails/password
    @Override
    public void configure(AuthenticationManagerBuilder authbuilder){
      authbuilder.userDetails(userDetailsService)
                 .passwordEncoder(passwordEncoder());
    }
    
    // This means we use a custom authentication
    @Bean(BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
    
    // the specific provider's encode algorithm for user detail's password 
    @Bean
     public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // set up who can access the views(web pages)
    @Override
    public void configure(HttpSecurity http){
      http.cors().and().csrf().disable()
          /* we might have such 
             
             // it will activate for unqualified user
             .exceptionHandling()
             .authenticationEntryPoint(unauthorizedHandler)
             
             // cache (used for e.g. Remember Me)
             .sessionManagement()
             .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
             
             .antMachers(method.XXX,"index") // this index
             .permitall()       // it allows everyone to access

             .anyRequest() // client request
             .authenticated() // requests needs authentication
          */
      // A custom security filter
      http.addFilterBefore(method(), method.class)
    }
}
```

## With `@EnableGlobalMethodSecurity`

### `securedEnabled`

This protects the controller/service
```java
// ADMIN can access getAllUsers
@Secured("ROLE_ADMIN")
public User getAllUsers() {}

// USER and ADMIN can access getUser method
@Secured({"ROLE_USER", "ROLE_ADMIN"})
public User getUser(Long id) {}

@Secured("IS_AUTHENTICATED_ANONYMOUSLY")
public boolean isUsernameAvailable() {}
```

### jsr250Enabled same as `@secured()`

```java
/* Both are the same but with different Framework Standard */ 

@Secured({"ROLE_USER", "ROLE_ADMIN"})
public User getUser(Long id) {
  //..
}

@RolesAllowed({"ROLE_USER","ROLE_ADMIN"})
public User getUser(Long id) {
  //...
}
```

### prePostEnabled
It enables more complex expression based access control syntax with @PreAuthorize and @PostAuthorize annotations
```java
@PreAuthorize("isAnonymous()")
public boolean isUsernameAvailable() {}

@PreAuthorize("hasRole('USER')")
public Poll createPoll() {}
```


## Interface UserdetailsService

To load/fetch the user details for the authentication we need the implementations of UserdetailsService


In the implementation, We’ll also define a custom UserPrincipal class that will implement UserDetails interface, and return the UserPrincipal object from overridden method `loadUserByUsername()`.

So we always need implementation of UserdetailsService interface to fetch the sensitive information of user (e.g. password, token … etc)

## 401 error

To return 401 unauthorized error for the users/clients who try to access a protected resource on server without **proper authentication**

- We can customize 401 error unauthorized error by implementing AuthenticationEntryPoint interface

#### Custom Security AuthenticationEntryPoint

AuthenticationEntryPoint interface proivdes `commence()` method to throw an exception for users/clients with unproper authentication

```java
package com.example.polls.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationEntryPoint.class);
    @Override
    public void commence(HttpServletRequest httpServletRequest,
                         HttpServletResponse httpServletResponse,
                         AuthenticationException e) throws IOException, ServletException {
        logger.error("Responding with unauthorized error. Message - {}", e.getMessage());
        httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, e.getMessage());
    }
}
```

## Custom Filter

A Custom Filter often is used to JWT check

Main design of JWT filter follows (normally) the following steps
- reads JWT authentication token from the Authorization header of all the requests
- validates the token
- loads the user details associated with that token.
- Sets the user details in Spring Security’s SecurityContext. Spring Security uses the user details to perform authorization checks. We can also access the user details stored in the SecurityContext in our controllers to perform our business logic.

```java
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtTokenProvider tokenProvider;

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            String jwt = getJwtFromRequest(request);

            if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
                Long userId = tokenProvider.getUserIdFromJWT(jwt);

                UserDetails userDetails = customUserDetailsService.loadUserById(userId);
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception ex) {
            logger.error("Could not set user authentication in security context", ex);
        }

        filterChain.doFilter(request, response);
    }

    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7, bearerToken.length());
        }
        return null;
    }
}
```

##  AuthenticationManagerBuilder and AuthenticationManager

`AuthenticationManagerBuilder` is used to create an AuthenticationManager instance which is the main Spring Security interface for authenticating a user.

- You can use AuthenticationManagerBuilder to build in-memory authentication, LDAP authentication, JDBC authentication, or add your custom authentication provider.

In our example, we’ve provided our customUserDetailsService and a passwordEncoder to build the AuthenticationManager.

In short we need to use `AuthenticationManagerBuilder` to configure our `AuthenticationManager` for this Web Security implementation (from `WebSecurityConfigurerAdapter` interfacce)



## Custom Business Excpetions

The APIs will throw exceptions if the request is not valid or some unexpected situation occurs.

To define Custom HttpStatus Exceptions we need annotations `@ResponseStatus`

```java
@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
public class AppException extends RuntimeException {
    public AppException(String message) {
        super(message);
    }

    public AppException(String message, Throwable cause) {
        super(message, cause);
    }
}

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class BadRequestException extends RuntimeException {

    public BadRequestException(String message) {
        super(message);
    }

    public BadRequestException(String message, Throwable cause) {
        super(message, cause);
    }
}

@ResponseStatus(HttpStatus.NOT_FOUND)
public class ResourceNotFoundException extends RuntimeException {
    private String resourceName;
    private String fieldName;
    private Object fieldValue;

    public ResourceNotFoundException( String resourceName, String fieldName, Object fieldValue) {
        super(String.format("%s not found with %s : '%s'", resourceName, fieldName, fieldValue));
        this.resourceName = resourceName;
        this.fieldName = fieldName;
        this.fieldValue = fieldValue;
    }

```


## User model for OAuth2

```java
package com.example.springsocial.model;
import com.fasterxml.jackson.annotation.JsonIgnore;

import javax.persistence.*;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotNull;

@Entity
@Table(name = "users", uniqueConstraints = {
        @UniqueConstraint(columnNames = "email")
})
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    @Email
    @Column(nullable = false)
    private String email;

    private String imageUrl;

    @Column(nullable = false)
    private Boolean emailVerified = false;

    @JsonIgnore
    private String password;

    // this is important
    //  to check you are logging in with google, local, facebook … etc
    @NotNull
    @Enumerated(EnumType.STRING)
    private AuthProvider provider;

    private String providerId;

    // Getters and Setters (Omitted for brevity)
}
```

```java
package com.example.springsocial.model;

public enum  AuthProvider {
    local,
    facebook,
    google,
    github
}
```

## Security Config for OAuth2Authentication
 
```java
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(
        securedEnabled = true,
        jsr250Enabled = true,
        prePostEnabled = true
)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // this is for local login
    //  to get user's details by local database
    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean(BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    // Configure A AuthenticationManager 
    //  for loing in via fetching the local database
    @Override
    public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder
                .userDetailsService(customUserDetailsService)
                .passwordEncoder(passwordEncoder());
    }

    // this is for login via google, facebook .. third part authorizations
    //  to get user's details by third part authorizations
    @Autowired
    private CustomOAuth2UserService customOAuth2UserService;




    // our custom filter (normally is for filtering the token)
    @Bean
    public TokenAuthenticationFilter tokenAuthenticationFilter() {
        return new TokenAuthenticationFilter();
    }



    // Configure our http-security (web pages)

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .cors()
                    .and()
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    .and()
                .csrf()
                    .disable()
                .formLogin()
                    .disable()
                .httpBasic()
                    .disable()
                .exceptionHandling()
                    .authenticationEntryPoint(new RestAuthenticationEntryPoint())
                    .and()
                .authorizeRequests()
                    .antMatchers("/",
                        "/error",
                        "/favicon.ico",
                        "/**/*.png",
                        "/**/*.gif",
                        "/**/*.svg",
                        "/**/*.jpg",
                        "/**/*.html",
                        "/**/*.css",
                        "/**/*.js")
                        .permitAll()
                    // Anyone can acces loging in in via local
                    //  or loging in by facebook, google …
                    .antMatchers("/auth/**", "/oauth2/**")
                        .permitAll()
                    .anyRequest()
                        .authenticated()
                    .and()
                .oauth2Login()
                    .authorizationEndpoint()
                        .baseUri("/oauth2/authorize")
                        .authorizationRequestRepository(cookieAuthorizationRequestRepository())
                        .and()
                    .redirectionEndpoint()
                        .baseUri("/oauth2/callback/*")
                        .and()
                    .userInfoEndpoint()
                        .userService(customOAuth2UserService)
                        .and()
                    .successHandler(oAuth2AuthenticationSuccessHandler)
                    .failureHandler(oAuth2AuthenticationFailureHandler);

        // Add our custom Token based authentication filter
        http.addFilterBefore(tokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }
```

## OAuth2 login flow

The OAuth2 login flow will be initiated by the frontend client by sending the user to the endpoint 
> `http://localhost:8080/oauth2/authorize/{provider}?redirect_uri=<redirect_uri_after_login>`

- The `{provider}` is  path parameter one of google, facebook, or github. 

- The `{redirect_uri}` is the URI to which the user will be redirected once the authentication with the OAuth2 provider is successful. 
- This is different from the OAuth2 redirectUri.

### Redirect the user to the AuthorizationURL of the supplied provider

This means if we want to signup/login by third part authorization, we will be redirected to the web page where third part authorization provides

this web page will ask us to allow/denies permission via third part account(e.g. google account, …) to the app(the website that you are trying signup/log in )  

the provider will redirect the user to the callback url `http://localhost:8080/oauth2/callback/{provider}` with an authorization code.  
If the user denies the permission, he will be redirected to the same callbackUrl but with an error.  

> If the OAuth2 callback results in an error, Spring security will invoke the oAuth2AuthenticationFailureHandler specified in the above SecurityConfig.
> If the OAuth2 callback is successful and it contains the authorization code, Spring Security will exchange the authorization_code for an access_token and invoke the customOAuth2UserService specified in the above SecurityConfig.


### Oauth2 UserDetailService retrives the user information

The customOAuth2UserService retrieves the details of the authenticated user and creates a new entry in the database or updates the existing entry with the same email.

This part is where we really get user information from third part authorization(google, facebook....)

### Retrun A User Details

Finally, the oAuth2AuthenticationSuccessHandler is invoked. It creates a JWT authentication token for the user and sends the user to the redirect_uri along with the JWT token in a query string.


## Define Repository for Oauth2

## Custom OAuth2 User Service

The CustomOAuth2UserService extends Spring Security’s DefaultOAuth2UserService and implements its loadUser() method. This method is called after an access token is obtained from the OAuth2 provider.

we first fetch the user’s details from the OAuth2 provider. If a user with the same email already exists in our database then we update his details, otherwise, we register a new user.

```java
@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);

        try {
            return processOAuth2User(oAuth2UserRequest, oAuth2User);
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            // Throwing an instance of AuthenticationException will trigger the OAuth2AuthenticationFailureHandler
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }

    // Via Request information(e.g. email) to fetch the user details in the third part
    //    application
    private OAuth2User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) {
        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(oAuth2UserRequest.getClientRegistration().getRegistrationId(), oAuth2User.getAttributes());
        if(StringUtils.isEmpty(oAuth2UserInfo.getEmail())) {
            throw new OAuth2AuthenticationProcessingException("Email not found from OAuth2 provider");
        }

        Optional<User> userOptional = userRepository.findByEmail(oAuth2UserInfo.getEmail());
        User user;
        if(userOptional.isPresent()) {
            user = userOptional.get();
            if(!user.getProvider().equals(AuthProvider.valueOf(oAuth2UserRequest.getClientRegistration().getRegistrationId()))) {
                throw new OAuth2AuthenticationProcessingException("Looks like you're signed up with " +
                        user.getProvider() + " account. Please use your " + user.getProvider() +
                        " account to login.");
            }
            user = updateExistingUser(user, oAuth2UserInfo);
        } else {
            user = registerNewUser(oAuth2UserRequest, oAuth2UserInfo);
        }

        return UserPrincipal.create(user, oAuth2User.getAttributes());
    }

    // If user are sign up via third part application 
    private User registerNewUser(OAuth2UserRequest oAuth2UserRequest, OAuth2UserInfo oAuth2UserInfo) {
        User user = new User();

        user.setProvider(AuthProvider.valueOf(oAuth2UserRequest.getClientRegistration().getRegistrationId()));
        user.setProviderId(oAuth2UserInfo.getId());
        user.setName(oAuth2UserInfo.getName());
        user.setEmail(oAuth2UserInfo.getEmail());
        user.setImageUrl(oAuth2UserInfo.getImageUrl());
        return userRepository.save(user);
    }

    // if user are login via third part application 
    private User updateExistingUser(User existingUser, OAuth2UserInfo oAuth2UserInfo) {
        existingUser.setName(oAuth2UserInfo.getName());
        existingUser.setImageUrl(oAuth2UserInfo.getImageUrl());
        return userRepository.save(existingUser);
    }

}
```

## Userinfo in OAuth2


Each Third part application are response userInfo via JSON
Each Third part application payload will be different
So we might need to create a abstract class and extend it as a custom class for handling different third part json response


A Base Userinfo in OAuth2 would have these
```java
public abstract class OAuth2UserInfo {
    
    // To store Json response from third part
    protected Map<String, Object> attributes;

    public OAuth2UserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    public Map<String, Object> getAttributes() {
      return attributes;
    }

    public abstract String getId();

    public abstract String getName();

    public abstract String getEmail();

    public abstract String getImageUrl();
}
```

we can extend the userinfo to defining custom third part userInfo(storing the info from google/facebook account etc...)

```java
public class FacebookOAuth2UserInfo extends OAuth2UserInfo {
    public FacebookOAuth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() {
        return (String) attributes.get("id");
    }

    @Override
    public String getName() {
        return (String) attributes.get("name");
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    @Override
    public String getImageUrl() {
        if(attributes.containsKey("picture")) {
            Map<String, Object> pictureObj = (Map<String, Object>) attributes.get("picture");
            if(pictureObj.containsKey("data")) {
                Map<String, Object>  dataObj = (Map<String, Object>) pictureObj.get("data");
                if(dataObj.containsKey("url")) {
                    return (String) dataObj.get("url");
                }
            }
        }
        return null;
    }
}
```

## Google

```java
public class GoogleOAuth2UserInfo extends OAuth2UserInfo {

    public GoogleOAuth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() {
        return (String) attributes.get("sub");
    }

    @Override
    public String getName() {
        return (String) attributes.get("name");
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    @Override
    public String getImageUrl() {
        return (String) attributes.get("picture");
    }
}
```

## Github

```java
public class GithubOAuth2UserInfo extends OAuth2UserInfo {

    public GithubOAuth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() {
        return ((Integer) attributes.get("id")).toString();
    }

    @Override
    public String getName() {
        return (String) attributes.get("name");
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    @Override
    public String getImageUrl() {
        return (String) attributes.get("avatar_url");
    }
}
```

## Usertails interface


We have to implement 2 interface
1. userdetails
2. OAuth2user

```java
public class UserPrincipal implements OAuth2User, UserDetails {
    private Long id;
    private String email;
    private String password;
    private Collection<? extends GrantedAuthority> authorities;
    private Map<String, Object> attributes;

    public UserPrincipal(Long id, String email, String password, Collection<? extends GrantedAuthority> authorities) {
        this.id = id;
        this.email = email;
        this.password = password;
        this.authorities = authorities;
    }

    public static UserPrincipal create(User user) {
        List<GrantedAuthority> authorities = Collections.
                singletonList(new SimpleGrantedAuthority("ROLE_USER"));

        return new UserPrincipal(
                user.getId(),
                user.getEmail(),
                user.getPassword(),
                authorities
        );
    }

    public static UserPrincipal create(User user, Map<String, Object> attributes) {
        UserPrincipal userPrincipal = UserPrincipal.create(user);
        userPrincipal.setAttributes(attributes);
        return userPrincipal;
    }

    public Long getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    public void setAttributes(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String getName() {
        return String.valueOf(id);
    }
}
```

## Get Authenticated CurrentUser


### Define A Annotation called CurrentUser
```java
package com.example.springsocial.security;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import java.lang.annotation.*;

@Target({ElementType.PARAMETER, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@AuthenticationPrincipal
public @interface CurrentUser {

}
```

### Create A Controller to get current user

```java
@RestController
public class UserController {

    @Autowired
    private UserRepository userRepository;

    @GetMapping("/user/me")
    @PreAuthorize("hasRole('USER')")
    public User getCurrentUser(@CurrentUser UserPrincipal userPrincipal) {
        return userRepository.findById(userPrincipal.getId())
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userPrincipal.getId()));
    }
}
```
## Utility classes for state (cookies) 

```java
public class CookieUtils {

    public static Optional<Cookie> getCookie(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();

        if (cookies != null && cookies.length > 0) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(name)) {
                    return Optional.of(cookie);
                }
            }
        }

        return Optional.empty();
    }

    public static void addCookie(HttpServletResponse response, String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(maxAge);
        response.addCookie(cookie);
    }

    public static void deleteCookie(HttpServletRequest request, HttpServletResponse response, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null && cookies.length > 0) {
            for (Cookie cookie: cookies) {
                if (cookie.getName().equals(name)) {
                    cookie.setValue("");
                    cookie.setPath("/");
                    cookie.setMaxAge(0);
                    response.addCookie(cookie);
                }
            }
        }
    }

    public static String serialize(Object object) {
        return Base64.getUrlEncoder()
                .encodeToString(SerializationUtils.serialize(object));
    }

    public static <T> T deserialize(Cookie cookie, Class<T> cls) {
        return cls.cast(SerializationUtils.deserialize(
                        Base64.getUrlDecoder().decode(cookie.getValue())));
    }
}
```


## Exception Class for OAuth2

```java
package com.example.springsocial.exception;

import org.springframework.security.core.AuthenticationException;

public class OAuth2AuthenticationProcessingException extends AuthenticationException {
    public OAuth2AuthenticationProcessingException(String msg, Throwable t) {
        super(msg, t);
    }

    public OAuth2AuthenticationProcessingException(String msg) {
        super(msg);
    }
}
```
