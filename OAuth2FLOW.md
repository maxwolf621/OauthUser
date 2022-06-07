[More Details](https://datatracker.ietf.org/doc/html/rfc6749#section-1.1)  
[Good Explanation](http://www.ruanyifeng.com/blog/2019/04/oauth-grant-types.html)  
[Google API login SetUp](https://xenby.com/b/245-%E6%95%99%E5%AD%B8-google-oauth-2-0-%E7%94%B3%E8%AB%8B%E8%88%87%E4%BD%BF%E7%94%A8%E6%8C%87%E5%8D%97)  
[The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)  
[Attributes of Different Third Parties](https://blog.yorkxin.org/posts/oauth2-implementation-differences-among-famous-sites.html)

## Basic Oauth2 User Login Flow via GITHUB
- [SpringBoot github oauth2login](https://medium.com/swlh/spring-boot-oauth2-login-with-github-88b178e0c004)  
    - [Demo](https://github.com/maxwolf621/OauthUser/tree/main/demo)  

# Oauth2 FLOW

```diff
User         Client(frontend)   SpringAPI         Provider
 '-----1------------+---------------+------->-------'
                                    +<------2-------'
	                            '-------3------>+
                                    +<------4-------'
                                    '-------5-------+
```
1. `User` access `Client`，`Client` redirects to `Provider`(e.g. GITHUB, ...)
   - `Provider` asks `User` for granting `Client` to access third party application account (**User enters 3rd part application account**) 
2. `Provider` response HTTP payload withing Authorization Code after the user successfully logs in 3rd part account
3. `Spring API` uses Authorization Code to fetch access token from `Provider`
4. `Provider` _Authenticates_ Authorization Code and responses _Access Token_ to `Spring API`
5. `Spring API` calls UserInfo-API with Access Token to access resource in `Provider`

```diff
		     +----------+ 
		     | Resource |
		     |   Owner  |
		     +----------+
			  ^
			  |
			 (B)
			  |
-		     +----|-----+          Client Identifier      +---------------+
-		     |          |>---(A)-- & Redirection URI ---->|               |
		     |  User-   |                                 | Authorization |
		     |  Agent   |>---(B)-- User authenticates --->|     Server    |
		     |          |                                 |               |
		     |          |<---(C)-- Authorization Code ---<|               |
		     +-|----|---+                                 +---------------+
		       |    |                                         ^      v
		      (A)  (C)                                        |      |
		       |    |                                         |      |
		       ^    v                                         |      |
		     +---------+                                      |      |
	+-----+	     |         |>---(D)-- Authorization Code ---------'      |
	|user |-(.)->|  Client |          & Redirection URI                  |
	+-----+	     |         |                                             |
		     |         |<---(E)----- Access Token -------------------'
		     +---------+       (w/ Optional Refresh Token)
```
[Definitions in Oauth2](https://stackoverflow.com/questions/12482070/how-does-a-user-register-with-oauth)
[Auth Code Grant Flow](https://blog.yorkxin.org/posts/oauth2-4-1-auth-code-grant-flow.html)   

- Resource Owner (Your third party application Account)  
- Client (The Application you are currently using (e.g. backend+frontend))  
- (Identity) Provider (Third Party Application authenticates the identity : Google, Facebook, Twitter, etc...)  
- Resource Server (Third Party Application's Server, e.g. Authorization Server, Resource Server, etc ... )  
- Resources (Resources in third party application that you are trying to access via the 3rd part application account)  

**(.)** The User Accesses The Client (The Spring Application(e.g. frontend)) 

**(A)** The client initiates the flow by **directing the resource owner's user-agent to the authorization endpoint**.
- The client includes these information and offers them to provider
  1. client identifier
  2. requested `scope
  3. local `state`
  4. `redirect_uri` tells the authorization server where the user-agent back once the user granted/denied the access (to the third party application)

**(B)** The authorization server authenticates the resource owner and **establishes** whether the resource owner grants/denies the client's access request.

**(C)** Assuming if the resource owner grants access, the authorization server redirects the user-agent back to the client via the `redirect_uri` provided earlier.  
- The redirection URI includes an `authorization code` and any local `state` provided by the client earlier.  
For example :  
  ```diff
  + accounts.google.com/o/oauth2/v2/auth?
  + response_type=code&
  - client_id=1506772512345-78tlj6v2mm12356lhodqr9t5br5fu57asxz.apps.googleusercontent.com&
  + scope=openid+profile+email&state=QFWkpSxvN-zs5gGoMCnFGDJDTYF1HZg1FC_5l31H0qg%3D&
  - `edirect_uri=http%3A%2F%2Flocalhost%3A8080%2Flogin%2Foauth2%2Fcode%2Fgoogle.
  ```

**(D)** The client requests an access token from the authorization server's token endpoint by including the authorization code received in the previous step. 

**(E)** The authorization server authenticates the client, validates the authorization code, and ensures that the redirection URI received matches the URI used to redirect the client in step (C). **If valid, the authorization server responds back with an access token and, optionally, a refresh token.**  

## Endpoint
- [Protocol Endpoints](https://datatracker.ietf.org/doc/html/rfc6749#section-3)  

![image](https://user-images.githubusercontent.com/68631186/122627719-db47c700-d0e3-11eb-9c9b-9c8f3743c623.png)  
- **Authorization Endpoint(used by client)**
Authorization Server issues Authorization Grant (intercepted by `OAuth2AuthorizationRequestRedirectFilter`)

- **Redirection Endpoint(used by authorization server)**  
Client receives Authorization Grant(intercepted by `LoginAuthenticationFilter`)

- Token Endpoint  
Authorization Server issues Access Token

## Oauth2 Setup 

### in Maven  

```xml
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-oauth2-client</artifactId>
</dependency>
```
### Add client-registration details in `application.properties`
```
spring.security.oauth2.client.registration.github.client-id = 
spring.security.oauth2.client.registration.github.client-secret =
spring.security.oauth2.client.registration.github.redirect-uri = 
```

### SpringBoot Web Security OAuth2 Configuration  
- [Configure the authorization of the ROLE](https://stackoverflow.com/questions/36233910/custom-http-security-configuration-along-with-oauth2-resource-server)

```java
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter{
    
    @Override
    public void configure(HttpSecurity http) throws Exception{
        http.authorizeRequests()
                .anyRequest()
                    .authenticated()
                .and()
                .oauth2Login();
    }
}
```

Accessing default host `localhost:8080` it will direct to the AuthorizedEndpoint (login page of the 3rd party application) after execute `mvn spring boot:run` 

After the user entered the password and the email of the 3rd party application account, it might have two results
1. It failed then it redirects to `http://localhost:8080/oauth2/authorization/github`    
2. It succeeded then the request sent by client is getting handled by `OAuth2AuthorizationRequestRedirectFilter`

Internally the implementation which implements `doFilterInternal` that matches against the `/oauth2/authorization/github` URI and redirect the request to
```diff
+ https://github.com/login/oauth/authorize?
- response_type=code&
- client_id=<clientId>&
- scope=read:user&state=<state>&
- redirect_uri=http://localhost:8080/login/oauth2/code/github
```
- `redirect_uri` is same as the one we registered our `application.properties`.  

After the User successfully authenticates against GitHub, the user will be redirected to (default) `http://localhost:8080/login/oauth2/code/github` with the authentication code in the request parameters.  
This will be handled by the `OAuth2LoginAuthenticationFilter`, which will perform a `POST` request to the GitHub API to get an Access Token.  
With AccessToken the Spring API calls implementation (e.g `Oauth2User` ) to access resource of Provider  

# Configure The OAuth2 Client

```java
@EnableWebSecurity
public class OAuth2ClientSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.oauth2Client()
                .clientRegistrationRepository(
                    this.clientRegistrationRepository())
                .authorizedClientRepository(
                    this.authorizedClientRepository())
                .authorizedClientService(
                    this.authorizedClientService())
                .authorizationCodeGrant()
    }
}
```
- We can configure client registration via java configuration or `application.properties`  

## MODEL of Client Registration 
A client registration holds these (The Most Important) information  
```diff
- client id 	
- client secret
- authorization grant type 
- scope(s) 
+ redirect URI 
+ authorization URI
+ token URI
```

### ClientRegistrationRepository   

**This repository provides the ability to retrieve a sub-set of the primary client registration information, which is stored with the Authorization Server.* 

- Spring Boot 2.x auto-configuration binds each of the properties under `spring.security.oauth2.client.registration.[registrationId]` to an instance of `ClientRegistration` and then composes each of the `ClientRegistration` instance(s) within a `ClientRegistrationRepository`. [EXAMPLE CODE](https://www.baeldung.com/spring-security-5-oauth2-login)  

For example :: get the registration information of client(the application) stored in Google(third part application) via `clientRegistrationRepository`
```java
@Controller
public class OAuth2ClientController {

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @GetMapping("/")
    public String index() {
        ClientRegistration GoogleRegistration =
            // A instance of ClientRegistration 
            // which it's (attribute) RegistrationId 
            // is "google"
            this.clientRegistrationRepository.findByRegistrationId("Google");
        
        // ...
        
        return "index";
    }
}
```

## Oauth2 Authentication Configuration

## `OAuth2AuthorizedClientProvider`

A strategy for authorizing (or re-authorizing) **an OAuth 2.0 Client (The Application that The user are currently using)**  

```diff
AuthorizedClientManager
 '- OAuth2AuthorizedClientProvider
+   '->Oauth2AccessToken 
       '-> OAuth2AuthorizedClientService 
           '-- associate -- OAuth2AuthorizedClientRepository
+	       '-- return -- OAuth2AuthorizedClient
```

An Oauth2 Authorized provider must provide these to build up  authentication procedure
- `ClientRegistration` is a representation of a client registered with an OAuth 2.0 or OpenID Connect 1.0 Provider.  
- `OAuth2AuthorizedClient` is a representation of an Authorized Client.
 
`Oauth2AuthorizedClientProvider` **DELEGATES** the persistence of an `OAuth2AuthorizedClient`, typically ***using an `OAuth2AuthorizedClientService` or `OAuth2AuthorizedClientRepository` provides lookup associated with the `clientOAuth2AccessToken`*** 
- [Oauth2AuthorizedClientProvider Example](https://www.programmersought.com/article/10451235590/)  

### `OAuth2AuthorizedClient`

For **a client is considered to be authorized** when the end-user/Resource Owner has **GRANTED** authorization to the client to access its protected resources.

```java
public class OAuth2AuthorizedClient implements Serializable {
	/**
	 * Constructs an OAuth2 Authorized Client 
     * using the following provided parameters. 
	 * @param clientRegistration
     *  the authorized client's registration
	 * @param principalName       
     *  the name of the End-User 
     *  {@code Principal} (Resource Owner)
	 * @param accessToken
     *  the access token credential granted
	 * @param refreshToken        
     *  the refresh token credential granted
	 */
	public OAuth2AuthorizedClient(
        ClientRegistration clientRegistration, 
		String principalName,
		OAuth2AccessToken accessToken, 
		@Nullable OAuth2RefreshToken refreshToken) {
		
		Assert.notNull(
            clientRegistration, 
            "clientRegistration cannot be null");
		
        Assert.hasText(
            principalName, 
            "principalName cannot be empty");
		
        Assert.notNull(
            accessToken, 
            "accessToken cannot be null");

		this.clientRegistration = clientRegistration;
		this.principalName = principalName;
		this.accessToken = accessToken;
		this.refreshToken = refreshToken;
	}
	
 	// ...
```

## `OAuth2AccessToken`

Construct an OAuth2 Access Token 

```java
public class OAuth2AccessToken extends AbstractOAuth2Token {	 
	 
	 /**
     * @param tokenType
     *  the token type
	 * @param tokenValue  
     *  the token value
	 * @param issuedAt
     *  the time at which the token was issued
	 * @param expiresAt    
     *  the expiration time on or after which the token MUST NOT be accepted
	 * @param scopes
     *  the scope(s) associated to the token
	 */
	public OAuth2AccessToken(
        TokenType tokenType, 
        String tokenValue,
        Instant issuedAt,
        Instant expiresAt) {

		this(tokenType, 
            tokenValue, 
            issuedAt, 
            expiresAt, 
            Collections.emptySet());
	}

    // construct with scopes
	public OAuth2AccessToken(
        TokenType tokenType,
        String tokenValue,
        Instant issuedAt, 
        Instant expiresAt,
        Set<String> scopes) {
		
        super(tokenValue, issuedAt, expiresAt);
		
        Assert.notNull(tokenType, "tokenType cannot be null");
		
        this.tokenType = tokenType;
		this.scopes = Collections.unmodifiableSet(
            (scopes != null) ? scopes : Collections.emptySet());
	}
	
	//...
```

## AuthorizedClientManager

The default implementation of `OAuth2AuthorizedClientManager` is `DefaultOAuth2AuthorizedClientManager`, which is associated with an `OAuth2AuthorizedClientProvider` that may support multiple authorization grant types using a delegation-based composite. 

- **The `OAuth2AuthorizedClientProviderBuilder` may be used to configure and build the delegation-based composite (e.g. password , emails ...).**
  - `OAuth2AuthorizedClientManager` needs two repositories ( `ClientRegistrationRepository`, `OAuth2AuthorizedClientRepository`)

Build Up the Custom OAuth2 Authorized Client Manager(For authentication) 
```java
@Bean
public OAuth2AuthorizedClientManager authorizedClientManager(
	
	// Third Party Application
	ClientRegistrationRepository clientRegistrationRepository;
	
    // Get an Authorized Client information
	OAuth2AuthorizedClientRepository authorizedClientRepository;

	/**
	 * Building/Configuring A Custom 
     *     {@code Oauth2AuthorizedClientProvider} 
	 * 設定要求使用者需要遞交哪些資料作為認證條件
	 */
	OAuth2AuthorizedClientProvider authorizedClientProvider =
	    OAuth2AuthorizedClientProviderBuilder.builder()
		    .authorizationCode()
		    .refreshToken()
		    .clientCredentials()
		    .password()
		    .build();

	// Build Manager 
    // via DefaultOAuth2AuthorizedClientManager 
    // With CustomProvider
	DefaultOAuth2AuthorizedClientManager authorizedClientManager =
	    new DefaultOAuth2AuthorizedClientManager(
            clientRegistrationRepository, authorizedClientRepository);
	
	// The construction of Provider 
    // is based on clientRegistrationRepository 
    // and authorizedClientRepository
	authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

	return authorizedClientManager;
}
```

## `contextAttributeMapper` 

If we need the `OAuth2AuthorizedClientProvider` requires the resource owner(end user)’s username and password to be available in `OAuth2AuthorizationContext.getAttributes().`

```java
@Bean
public OAuth2AuthorizedClientManager authorizedClientManager(
        // 3rd part application Registration 
        ClientRegistrationRepository clientRegistrationRepository,
        // 3rd part application user account
        OAuth2AuthorizedClientRepository authorizedClientRepository) {
    
    // Authentication Provider
    OAuth2AuthorizedClientProvider authorizedClientProvider =
            OAuth2AuthorizedClientProviderBuilder.builder()
                    .password()
                    .refreshToken()
                    .build();

    DefaultOAuth2AuthorizedClientManager authorizedClientManager =
            new DefaultOAuth2AuthorizedClientManager(
                clientRegistrationRepository, 
                authorizedClientRepository);
    authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

    // 1. Assuming the `username` and `password` 
    //    are supplied as `HttpServletRequest` parameters,
    // 2. The Instance of DefaultOAuth2AuthorizedClientManager 
    //    is designed to be used within 
    //    the context of a `HttpServletRequest`. 
    authorizedClientManager.setContextAttributesMapper(contextAttributesMapper());

    return authorizedClientManager;
}

private Function <OAuth2AuthorizeRequest, Map<String, Object> > contextAttributesMapper() {
    return authorizeRequest -> {
        Map<String, Object> contextAttributes = 
                    Collections.emptyMap();
	
        HttpServletRequest servletRequest = 
                    authorizeRequest.getAttribute(HttpServletRequest.class.getName());
	
	// We get username and password 
    // from HttpServletRequest instance
        String username = servletRequest.getParameter(OAuth2ParameterNames.USERNAME);
        String password = servletRequest.getParameter(OAuth2ParameterNames.PASSWORD);

        if (StringUtils.hasText(username) && StringUtils.hasText(password)) {

            // create contextAttributes
            contextAttributes = new HashMap<>();
	    
            /**
             * `PasswordOAuth2AuthorizedClientProvider`
             * requires both attributes
             */
	    contextAttributes.put(
            OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, 
            username);
        contextAttributes.put(
            OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, 
            password);
        }
        return contextAttributes;
    };
}   
```

### `AuthorizedClientServiceOAuth2AuthorizedClientManager`

- [Diff btw AuthorizedClientServiceOAuth2AuthorizedClientManager and DefaultOAuth2AuthorizedClientManager](https://stackoverflow.com/questions/67500742/what-is-the-difference-between-defaultoauth2authorizedclientmanager-and-authoriz)  

When operating data outside of a `HttpServletRequest` context(e.g `clientRegistrationId`, principal name ...etc), use `AuthorizedClientServiceOAuth2AuthorizedClientManager` instead. 

For Example
```java
@Bean
public OAuth2AuthorizedClientManager authorizedClientManager(
        ClientRegistrationRepository clientRegistrationRepository,
        OAuth2AuthorizedClientService authorizedClientService) {

    /**
     * Authenticate with attributes in client registration
     * not from HttpServletRequest (e.g. password , username , token ... etc)
     */
    OAuth2AuthorizedClientProvider authorizedClientProvider =
            OAuth2AuthorizedClientProviderBuilder.builder()
                    .clientCredentials()
                    .build();
		    
    /* here we use ServiceOAuth2AuthorizedClientManager */
    AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientManager =
            new AuthorizedClientServiceOAuth2AuthorizedClientManager(
                clientRegistrationRepository,
                authorizedClientService);
    
    authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

    return authorizedClientManager;
}
```

## `authorizationRequestRepository` (Authorization Endpoint)

The `authorizationRequestRepository` is responsible for the persistence of the `OAuth2AuthorizationRequest` from the time the Authorization Request is initiated to the time the Authorization Response is received (intercepted by `OAuth2LoginAuthenticationFilter`).

- It is Used by the `OAuth2AuthorizationRequestRedirectFilter` for persisting the `OAuth2AuthorizationRequest` before it initiates the authorization code grant flow.
  - As well, used by the `OAuth2LoginAuthenticationFilter` for resolving the associated Authorization Request when handling the callback of the Authorization Response.  

REVIEW of `OAuth2AuthorizationRequest`  
- A representation of an OAuth 2.0 **Authorization Request for the authorization code grant type or implicit grant type**. [code](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/oauth2/core/endpoint/OAuth2AuthorizationRequest.html)


### Create a custom AuthorizationRequestRepository  

Configure HttpSecurity to allow an custom Authorization Request Repository 
```java
@EnableWebSecurity
public class OAuth2ClientSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.oauth2Client(oauth2Client ->
                oauth2Client
                    .authorizationCodeGrant(authorizationCodeGrant ->
                        authorizationCodeGrant
                            .authorizationRequestRepository(this.authorizationRequestRepository())
                            //...
                    )
            );
    }
}
```

Oauth2User has default provider called `CommonOAuth2Provider` to fetch protected resource from google, github, ...
```java
public enum CommonOAuth2Provider {

  GOOGLE {

    @Override
    public Builder getBuilder(String registrationId) {
      ClientRegistration.Builder builder = getBuilder(registrationId,
          ClientAuthenticationMethod.BASIC, DEFAULT_REDIRECT_URL);
      builder.scope("openid", "profile", "email");
      builder.authorizationUri("https://accounts.google.com/o/oauth2/v2/auth");
      builder.tokenUri("https://www.googleapis.com/oauth2/v4/token");
      builder.jwkSetUri("https://www.googleapis.com/oauth2/v3/certs");
      builder.userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo");
      builder.userNameAttributeName(IdTokenClaimNames.SUB);
      builder.clientName("Google");
      return builder;
    }
  },

  GITHUB {

    @Override
    public Builder getBuilder(String registrationId) {
      ClientRegistration.Builder builder = getBuilder(registrationId,
          ClientAuthenticationMethod.BASIC, DEFAULT_REDIRECT_URL);
      builder.scope("read:user");
      builder.authorizationUri("https://github.com/login/oauth/authorize");
      builder.tokenUri("https://github.com/login/oauth/access_token");
      builder.userInfoUri("https://api.github.com/user");
      builder.userNameAttributeName("id");
      builder.clientName("GitHub");
      return builder;
    }
  },

  FACEBOOK {
    @Override
    public Builder getBuilder(String registrationId) {
      ClientRegistration.Builder builder = getBuilder(registrationId,
          ClientAuthenticationMethod.POST, DEFAULT_REDIRECT_URL);
      builder.scope("public_profile", "email");
      builder.authorizationUri("https://www.facebook.com/v2.8/dialog/oauth");
      builder.tokenUri("https://graph.facebook.com/v2.8/oauth/access_token");
      builder.userInfoUri("https://graph.facebook.com/me?fields=id,name,email");
      builder.userNameAttributeName("id");
      builder.clientName("Facebook");
      return builder;
    }
  },

  OKTA {

    @Override
    public Builder getBuilder(String registrationId) {
      ClientRegistration.Builder builder = getBuilder(registrationId,
          ClientAuthenticationMethod.BASIC, DEFAULT_REDIRECT_URL);
      builder.scope("openid", "profile", "email");
      builder.userNameAttributeName(IdTokenClaimNames.SUB);
      builder.clientName("Okta");
      return builder;
    }
  };

  /**
    * Default Redirect URL of {@code ClientRegistration}
    */
  private static final String DEFAULT_REDIRECT_URL = "{baseUrl}/{action}/oauth2/code/{registrationId}";

 
  protected final ClientRegistration.Builder getBuilder(
                                String registrationId,
                                ClientAuthenticationMethod method, 
                                String redirectUri) {
    ClientRegistration.Builder builder = ClientRegistration.withRegistrationId(registrationId);
    builder.clientAuthenticationMethod(method);
    builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
    builder.redirectUriTemplate(redirectUri);
    return builder;
  }
    
  public abstract ClientRegistration.Builder getBuilder(String registrationId);

}
```

## Oauth2 Authentication Introspecter to form valid `Oauth2AuthenticatedPrincipal`

It decodes `String` tokens into validated instances of `OAuth2AuthenticatedPrincipal`
The default `QpaueTokenIntrospector` exposes itself as a bean to be injected

```java
@Bean
public OpaqueTokenIntrospector introspector() {
    return new NimbusOpaqueTokenIntrospector(introspectionUri, clientId, clientSecret);
}
```

### Custom Introspector

creating a custom introspector (e.g. Extracting Authorities Manually) ...
```java
public class CustomAuthoritiesOpaqueTokenIntrospector implements OpaqueTokenIntrospector {
    private OpaqueTokenIntrospector delegate =
            new NimbusOpaqueTokenIntrospector("https://idp.example.org/introspect", "client", "secret");

    
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        // Decode the String Token to a valid Oauth2AuthenticatedPrincipal
        OAuth2AuthenticatedPrincipal principal = this.delegate.introspect(token);
	
        return new DefaultOAuth2AuthenticatedPrincipal(
                principal.getName(), principal.getAttributes(), extractAuthorities(principal));
    }

    private Collection<GrantedAuthority> extractAuthorities(OAuth2AuthenticatedPrincipal principal) {
        List<String> scopes = principal.getAttribute(OAuth2IntrospectionClaimNames.SCOPE);
        return scopes.stream()
                     .map(SimpleGrantedAuthority::new)
                     .collect(Collectors.toList());
    }
}
```

then expose it as bean
```java
@Bean
public OpaqueTokenIntrospector introspector() {
    return new CustomAuthoritiesOpaqueTokenIntrospector();
}
```
A custom introspector can 
- use `RestOperations` to configuring timeout
- create custom `JWTOpaueTokenIntrospector` by implementing `OpaqueTokenIntrospector`
