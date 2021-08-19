[Annotation for bean](https://segmentfault.com/a/1190000021679236)  
[shortcome of the field based constructor](https://zhuanlan.zhihu.com/p/337498135)  
[EnableGlobalMethodSecurity](https://matthung0807.blogspot.com/2019/09/spring-security-enableglobalmethodsecur.html)  
[RolesAllowed and PreAuthorize](https://stackoverflow.com/questions/43961625/rolesallowed-vs-preauthorize-vs-secured)  
[AutoWired and Bean](https://stackoverflow.com/questions/34172888/difference-between-bean-and-autowired)   
[EndPoint](https://docs.identityserver.io/en/latest/endpoints/userinfo.html)  

# Build Up A Web Security For Spring Boot

Normally We need these methods
1. Custom `UserDetailsService` to let our Authentication Provider fetch the user personal detail information   
   - For The Custom Authentication we need to expose our `AuthenticationManager` as a bean with annotation `@Bean(BeanIds.AUTHENTICATION_MANAGER)`  
2. Custom JWT Token Filter  
3. Configure(**BUILD UP**) the Authentication **Provider** via An `AuthenticationManager`'s `AuthenticationManagerBuilder` method   
4. Configure the each web page's security via `httpSecurity`  

## Web Security Configuration (build up user Authentication Implementation)

To Configure Spring Security via an Implementation of `WebSecurityConfigurerAdapter`  

```java
@Condiguration     
@EnableWebSecurity // Set Web Security On
@EnableGlobalMethodSecurity(
        securedEnabled = true,  //roles allowed
        jsr250Enabled = true,   //roles allowed with expression 
        prePostEnabled = true
)
@AllargsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter{
    
 
    /**
      * Inject a instance of CustomUserDetailsService via
      * {@code @Autowired} or {@code private final} + {@code @AllargsConstructor}
      * Get principal (user's details)
      */
    private final CustomUserDetailsServic userDetailsService;

    /**
      * Expose Custom Filter as a bean 
      * to be injected(added) in {@code http.addbeforefilter}
      */
    @Bean
    public CustomFilter customFilter(){
      return new customFilter();
    }

    /**
      * Build a AuthenticationProvider via AuthenticationManager
      *   Setup how this provider (e.g user details, password encoder
      */
    @Override
    public void configure(AuthenticationManagerBuilder authbuilder){
      authbuilder.userDetails(userDetailsService)
                 .passwordEncoder(passwordEncoder());
    }
    
    /**
     * Expose our Custom Provider 
     */
    @Bean(BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
    
    /**
      * Custom Provider's password encode algorithm 
      * (for user detail's password 
      */
    @Bean
     public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
      * Security For Http Protocol
      */
    @Override
    public void configure(HttpSecurity http){
      /** 
       * we might often have these to set up 
       */ 
      http.cors() // Allowing This Server access from different domain, httpProtocol...
          .and()
          .csrf().disable()
          .exceptionHandling()  //throw a 401 status error for unqualified user
            .authenticationEntryPoint(unauthorizedHandler)
          .sessionManagement() // cache (used for e.g. Remember Me, State)
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // Ceck the state via cookie
          .antMachers(method.GET/*or POST ..etc */ ,
                      "/our_Http_Index" /* http_index */)
            .permitall() // Allow this http index `/our_Http_Index` to be accessed by everyone with request 'GET' method
          .anyRequest()        // any other client request
            .authenticated()   // needs authentication
      http.addFilterBefore(method(), method.class) // A custom security filter to intercept the payloads
    }
}
```

##  `@EnableGlobalMethodSecurity`


### `securedEnabled`
It protects the `controller/service` layer with Specific Authorities

```java
// ADMIN can access this method
@Secured("ROLE_ADMIN")
public User getAllUsers() {}

// USER and ADMIN can access this method
@Secured({"ROLE_USER", "ROLE_ADMIN"})
public User getUser(Long id) {}

@Secured("IS_AUTHENTICATED_ANONYMOUSLY")
public boolean isUsernameAvailable() {}
```

### `jsr250Enabled` for `@RolesAllowed`

It's same as `@secured()` but with different framwork standard   

```java
@Secured({"ROLE_USER", "ROLE_ADMIN"})
public User getUser(Long id) {
  //..
}

@RolesAllowed({"ROLE_USER","ROLE_ADMIN"})
public User getUser(Long id) {
  //...
}
```

### `prePostEnabled`

It enables more complex expression based (e.g methods … ) access control syntax with `@PreAuthorize` and `@PostAuthorize` annotations   

```java
@PreAuthorize("isAnonymous()")
public boolean isUsernameAvailable() {}

@PreAuthorize("hasRole('USER')")
public Poll createPoll() {}
```

## Interface `UserdetailsService`
This interface loads/fetchs the user details (password, name, email etc... from database) for the authentication.   

In the implementation of this interface, We’ll also define a custom UserPrincipal class that implements `UserDetails` interface, and return  as the UserPrincipal object from overridden method `loadUserByUsername()` in implementation of UserDetailsService interface   

```java
@AllargsConstructor
public class CustomUserdetailsService implements UserdetailsService
  
  // A implementation of `UserDetails`
  private final CustomUserDetail customUserDetail;

  @Override
  public String loadbyUsername(String username){
    //...
    return customUserDetail;
  }
```

## redirect 401 error  

To return 401 unauthorized error for the users/clients who try to access a protected resource on server without **proper authentication**  
- We can customize 401 error unauthorized error by implementing `AuthenticationEntryPoint` interface  

### Custom Security `AuthenticationEntryPoint`

`AuthenticationEntryPoint` interface proivdes `commence()` method to throw an exception for users/clients with unproper authentication  

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

    // private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationEntryPoint.class);
    @Override
    public void commence(HttpServletRequest httpServletRequest,
                         HttpServletResponse httpServletResponse,
                         AuthenticationException e) throws IOException, ServletException {
        //logger.error("Responding with unauthorized error. Message - {}", e.getMessage());
        httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, e.getMessage());
    }
}
```

## Custom Filter
A Custom Filter is most used to create JWT filter  

Main design of JWT filter follows (normally) the following process  
- Reads 
  > JWT authentication token from the Authorization header of all the requests  
- Validating
  > The token that client provided  
- Loads 
  > The user details associated with that token  
- Set the **UserDetails** in Spring Security’s SecurityContext.  
  > Spring Security uses the class `UserDetails` to perform authorization checks.      
  > We can also access the user details stored in the `SecurityContext` in our controllers to perform our business logic.  

```java
public class JwtAuthenticationFilter extends OncePerRequestFilter {
/* first we get jwt from request payload 
    {Authorization : Bears OUR_JWT }
   then check the validity fo the fetched jwt
   get user_id 
   get user details via user_id
   set this user's details in Authentication
*/

    @Autowired
    private JwtTokenProvider tokenProvider;

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    //private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            String jwt = getJwtFromRequest(request);

            // via {@code getJwtFromRequest}  
            if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
                Long userId = tokenProvider.getUserIdFromJWT(jwt);
                
                /**
                  * check if this user is valid or not
                  */
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

    /**
      * {@code getHeader(String name)} get specific header name
      * {@code StringUti.hasText(String text)} check the text is null 
      * {@code startWith(String characters) check the name start with specific characters
      */
    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7, bearerToken.length());
        }
        return null;
    }
}
```

##  `AuthenticationManagerBuilder` and `AuthenticationManager`  

`AuthenticationManagerBuilder` is used to create an `AuthenticationManager` instance which is the main Spring Security interface for authenticating a user.  

For example we can use `AuthenticationManagerBuilder` to build in-memory authentication, LDAP authentication, JDBC authentication, or add your custom authentication provider.

In the above's example, it’ve provided `customUserDetailsService` and a `passwordEncoder` to build the `AuthenticationManager`.  
```java
//..
@Override
configure(AuthenticationManagerBuilder authProvider){
  authProvider.userDetails(this.customUserDetailsService())
              .passwordEncoder(this.passwordEncoder());
}
```
- we know that we need to use `AuthenticationManagerBuilder` to configure our `AuthenticationManager` for the Web Security interface `WebSecurityConfigurerAdapter`'s implementation

## Custom Business Excpetions

The APIs will throw exceptions if the request is not valid or some unexpected situation occurs.

To define Custom HttpStatus Exceptions we need annotations `@ResponseStatus`

```java
/* For Http Status is internal server error */
@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
public class AppException extends RuntimeException {
    public AppException(String message) {
        super(message);
    }

    public AppException(String message, Throwable cause) {
        super(message, cause);
    }
}

/* For Http Status Bad Request */
@ResponseStatus(HttpStatus.BAD_REQUEST)
public class BadRequestException extends RuntimeException {

    public BadRequestException(String message) {
        super(message);
    }

    public BadRequestException(String message, Throwable cause) {
        super(message, cause);
    }
}

/* For Http Satus 404 not found */
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

## OAuth2 Third Part Login via Google, Facebook, Github … 

The flow is kidda same as the above , but with a little difference
1. Add A Enum Provider model 
   > With `enum provider` member to let user choose login/signup by third part application (google, facebook...) or local application
2. Define A repository that implements `AuthorizationRequestRepository`
   > To help third part fetchs the user details in database
3. Define A Custom Service that implements `DefaultOAuth2UserService`
4. Create Abstract class `Auth2UserInfo`(For storing the retrieving User Details(Attributes) form 3rd party Appdlication)
   > So we might have Implementation of `Auth2UserInfo` for facebook, google, github ...
5. Create `OAuth2UserInfoFactory` Class (optional)
6. Create An Inheritance extending `OAuth2AuthenticationSuccessHandler` for success authentication 
7. Create An Inheritance extending `OAuth2AuthenticationFailureHandler` for failure authentication 
8. Create Custom Oauth2 User Principal implementing `OAuth2User`, `UserDetails`
9. Create Meta annotation for get `CurrentUser` from Spring Web Security (optional)
10. Create DTOs for (login(token) response, login request, sign request, ...)
11. Create Custom Business Excpetions (HttpStatus NOT_FOUND, BAD_REQUEST etc ...)
 
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

    /* Here is added a third part authorization */
    //  To check you are logging in with google, local, facebook … etc
    @NotNull
    @Enumerated(EnumType.STRING)
    private AuthProvider provider;

    private String providerId;

    // Getters and Setters (Omitted for brevity)
}
```

```java
public enum AuthProvider {
    local,
    facebook,
    google,
    github
}
```

## Web Security Config for OAuth2 Authentication

Configure httpSecurity with `http.oauth2login()`

```java
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(
        securedEnabled = true,
        jsr250Enabled = true,
        prePostEnabled = true
)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // Local User Service
    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    // Expose our custom AuthenticationManager for Local 
    @Bean(BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    // Configure a AuthenticationManager for a custom authentication provider
    @Override
    public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder
                .userDetailsService(customUserDetailsService)
                .passwordEncoder(passwordEncoder());
    }

    // Oauth2 User Service
    @Autowired
    private CustomOAuth2UserService customOAuth2UserService;

    // Jwt Token Filter
    @Bean
    public TokenAuthenticationFilter tokenAuthenticationFilter() {
        return new TokenAuthenticationFilter();
    }

   
    // http security
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors()
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
                .antMatchers("/")
                    .permitAll()
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
                .redirectionEndpoint()            //return the user's details from thrid part
                    .baseUri("/oauth2/callback/*")
                    .and()
                .userInfoEndpoint()
                    .userService(customOAuth2UserService)
                    .and()
                .successHandler(oAuth2AuthenticationSuccessHandler)
                .failureHandler(oAuth2AuthenticationFailureHandler);
        http.addFilterBefore(tokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }
```

## OAuth2 login flow

When we want to access 3rd party resource at first time, we will be redirected to the page where third party authorization provides (for fetching Auhorization Code)   
this web page(login page) will ask us to allow/denies the permission to access the 3rd party account  

The OAuth2 login flow will be initiated by the frontend client by sending the user to the endpoint 
- `http://localhost:8080/oauth2/authorize/{provider}?redirect_uri=<redirect_uri_after_login>`  
  > The `{provider}` is path parameter one of `google`, `facebook`, or `github`.   
  > The `{redirect_uri}` is the URI to which the user will be redirected once the authentication with the OAuth2 provider is successful.   

If the user granted (Successfully log In), the provider will redirect the user to the callback url (default url) `http://localhost:8080/oauth2/callback/{provider}` with an authorization code.  
Else if the user denies the permission, he will be redirected to the same callback Url but with an error query paramter on it.   

- Callback results in an error, Spring security will invoke the `oAuth2AuthenticationFailureHandler`
- Callback is successful and it will contain the authorization code, Spring security will exchange the authorization_code for an access_token and call the `OAuth2UserService`

The `OAuth2UserService` retrieves the details of the authenticated user and creates a new entry in the database or updates the existing entry with the same email.  
Finally, the `oAuth2AuthenticationSuccessHandler` is invoked.  It creates a JWT authentication token for the user and sends the user to the redirect_uri along with the JWT token in a query string.  

## Custom OAuth2 UserService

The CustomOAuth2UserService extends Spring Security’s `DefaultOAuth2UserService` and implements its `loadUser()` method.  
This method is called after an access token is obtained from the OAuth2 provider.   

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

    /** 
      * {@code OAuth2UserRequest.getClientRegistration().getRegistrationId()} provider
      * {@code Oauth2User.getAttributes()} attributes from 3rd party application 
      */
    private OAuth2User processOAuth2User(OAuth2UserRequest oAuth2UsedrRequest, OAuth2User oAuth2User) {
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

    // ... update/create ...

}
```

## Userinfo in OAuth2

For User Service To get different resources from different 3rd party application
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


Configure A Custom UserInfo for third party application's attributes  
for example google
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



## Implementation (Principal) of `Oauth2User` or `UserDetails`

Congiure the custom Principal via interface `UserDetails` and `Oauth2User`

`UserDetails` : for spring application  
`Oauth2User`  : for third party application

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

## Custom Annotation

We can define a custom Annotation called `CurrentUser`
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


We can Create A Controller to get current user
```java
@RestController
public class UserController {

    @Autowired
    private UserRepository userRepository;

    /**
      * with {@code @CurrentUser} to get Current User ID 
      */
    @GetMapping("/user/me")
    @PreAuthorize("hasRole('USER')")
    public User getCurrentUser(@CurrentUser UserPrincipal userPrincipal) {
        return userRepository.findById(userPrincipal.getId())
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userPrincipal.getId()));
    }
}
```
## Utility class for state (cookies) 

```java
public class CookieUtils {

    /**
      * @return {@code Optional<Cookie>}
      */
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


    /**
      * add cookie in the response via {@code addCoolie(Cookie cookie)}
      */
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


## `AuthenticationException` Exception for OAuth2

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
