[More Details](https://datatracker.ietf.org/doc/html/rfc6749#section-1.1)  
[Good Explanation](http://www.ruanyifeng.com/blog/2019/04/oauth-grant-types.html)  
[Google API loging SetUp](https://xenby.com/b/245-%E6%95%99%E5%AD%B8-google-oauth-2-0-%E7%94%B3%E8%AB%8B%E8%88%87%E4%BD%BF%E7%94%A8%E6%8C%87%E5%8D%97)  
[The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)  
# What Each Endpoint does 

## Endpoints
![image](https://user-images.githubusercontent.com/68631186/122627719-db47c700-d0e3-11eb-9c9b-9c8f3743c623.png)
- Authorization Endpoint作為Authorization Server發行Authorization Grant
- Redirection Endpoint作為Client接收Authorization Grant
- Token Endpoint作為Authorization Server發行Access Token



``````
 +--------+                               +---------------+
 |        |--(A)- Authorization Request ->*   Resource    |
 |        |                               |     Owner     |
 |        *<-(B)-- Authorization Grant ---|               |
 |        |                               +---------------+
 |        |
 |        |                               +---------------+
 |        |--(C)-- Authorization Grant -->* Authorization |
 | Client |                               |     Server    |
 |        |<-(D)----- Access Token -------*               |
 |        |                               +---------------+
 |        |
 |        |                               +---------------+
 |        |--(E)----- Access Token ------>|    Resource   |
 |        |                               |     Server    |
 |        |<-(F)--- Protected Resource ---|               |
 +--------+                               +---------------+
``````


An authorization grant is a credential representing the resource owner's authorization (to access its protected resources) used by the client to obtain an access token.  
This specification defines four grant types
1. authorization code
2. implicit其中 client_id 只有 Public Client 才需要提供，如果是 Confidential Client 或有拿到 Client Credentials ，就必須進行 Client 認證
3. resource owner password credentials
4. client credentials 
[More Details](https://blog.yorkxin.org/posts/oauth2-4-1-auth-code-grant-flow.html)  

###  User Agent
```
     +----------+
     | Resource |
     |   Owner  |
     |          |
     +----------+
          ^
          |
         (B)
     +----|-----+          Client Identifier      +---------------+
     |         -+----(A)-- & Redirection URI ---->|               |
     |  User-   |                                 | Authorization |
     |  Agent  -+----(B)-- User authenticates --->|     Server    |
     |          |                                 |               |
     |         -+----(C)-- Authorization Code ---<|               |
     +-|----|---+                                 +---------------+
       |    |                                         ^      v
      (A)  (C)                                        |      |
       |    |                                         |      |
       ^    v                                         |      |
     +---------+                                      |      |
     |         |>---(D)-- Authorization Code ---------'      |
     |  Client |          & Redirection URI                  |
     |         |                                             |
     |         |<---(E)----- Access Token -------------------'
     +---------+       (w/ Optional Refresh Token)
```
[Ref](https://datatracker.ietf.org/doc/html/rfc6749#section-3)  
- (A) The client initiates the flow by directing the resource owner's user-agent to the authorization endpoint. The client includes its client identifier, requested `scope`, local `state`, and a `redirection URI` to which the authorization server will send the user-agent back once access is granted (or denied).  
- (B) The authorization server authenticates the resource owner (via the user-agent) and **establishes** whether the resource owner grants or denies the client's access request.  
   ```json
   accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=150677252870-78tlj6v2mm653alhodqr9t5br5fu5bs0.apps.googleusercontent.com&scope=openid+profile+email&state=QFWkpSxvN-zs5gGoMCnFGDJDTYF1HZg1FC_5l31H0qg%3D&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Flogin%2Foauth2%2Fcode%2Fgoogle.
   ```
- (C) Assuming the resource owner grants access, the authorization server redirects the user-agent back to the client using the `redirection URI` provided earlier (in the request or during client registration).  
     - The redirection URI includes an authorization code and any local state provided by the client earlier.
- (D) The client requests an access token from the authorization server's token endpoint by including the authorization code received in the previous step. When making the request, the client authenticates with the authorization server. The client includes the redirection URI used to obtain the authorization code for verification.  
- (E). The authorization server authenticates the client, validates the authorization code, and ensures that the redirection URI received matches the URI used to redirect the client in step (C). **If valid, the authorization server responds back with an access token and, optionally, a refresh token.**
[ref](https://blog.yorkxin.org/posts/oauth2-4-1-auth-code-grant-flow.html)  


# Spring boot Oauth2User Authorization Flow
```java
@EnableWebSecurity
public class OAuth2ClientSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .oauth2Client()
                /*LogIn via Google, Facebook etc ... */
                .clientRegistrationRepository(this.clientRegistrationRepository())
                .authorizedClientRepository(this.authorizedClientRepository())
                .authorizedClientService(this.authorizedClientService())
                .authorizationCodeGrant()
                    .authorizationRequestRepository(this.authorizationRequestRepository())
                    .authorizationRequestResolver(this.authorizationRequestResolver())
                    .accessTokenResponseClient(this.accessTokenResponseClient());
    }
}
```
## Registration
To configure client registration via java configuration or application.properties 

### ClientRegistration
A client registration holds information, such as 
```
client id
client secret
authorization grant type
redirect URI
scope(s)
authorization URI
token URI
and other details
```

### ClientRegistrationRepository
This repository provides the ability to retrieve a sub-set of the primary client registration information, which is stored with the Authorization Server.

> Spring Boot 2.x auto-configuration binds each of the properties under `spring.security.oauth2.client.registration.[registrationId]` to an instance of ClientRegistration and then composes each of the `ClientRegistration` instance(s) within a `ClientRegistrationRepository`.

IF FRAMEWORK IS NOT SPRING BOOT THEN WE MUST DEFINE A `ClientRegistrationRepository` bean  
[EXAMPLE CODE HERE](https://www.baeldung.com/spring-security-5-oauth2-login)  

```java
@Controller
public class OAuth2ClientController {
    // use it to retrieve client registration information is stored
    //  and owned by the Authorization Server
    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @GetMapping("/")
    public String index() {
        ClientRegistration GoogleRegistration =
            // A instance of ClientRegistration which it's (attribute) RegistrationId is "google"
            this.clientRegistrationRepository.findByRegistrationId("Google");
        // ...
        return "index";
    }
}
```

## A strategy for authorizing (or re-authorizing) an OAuth 2.0 Client `OAuth2AuthorizedClientProvider`

`Oauth2AuthrizedClientProvider` delegats the persistence of an `OAuth2AuthorizedClient`, typically using an `OAuth2AuthorizedClientService` or `OAuth2AuthorizedClientRepository` provides lookup associated with the `clientOAuth2AccessToken`  
[Example](https://www.programmersought.com/article/10451235590/)  

Configure A Oauth2 AuthorizedClient Provider we need these 
- Model
  > Oauth2AuthorizedClient
- Repository
  > OAuth2AuthorizedClientRepository
- Service
  > OAuth2AuthorizedClientService

### OAuth2AuthorizedClient 
For a client is considered to be authorized when the end-user (Resource Owner) has granted authorization to the client to access its protected resources.
[Code of OAuth2AuthrizedClient](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/oauth2/client/OAuth2AuthorizedClient.html)  

A authorized client will contain
```
Auth2AccessToken	 the access token credential granted.
ClientRegistration       the authorized client's registration.
String 			 the End-User's (e.g, google, facebook, ...) Principal name.
OAuth2RefreshToken	 token credential granted.
```

### Build up a custom AuthorizedCientManager 

REVIEW
- xxx_Manager is based on xxx_Provider via xxx_ProviderBuilder
- xxx_Provider is based on the xxx_Repositories

The default implementation of `OAuth2AuthorizedClientManager` is `DefaultOAuth2AuthorizedClientManager`, which is associated with an `OAuth2AuthorizedClientProvider` that may support multiple authorization grant types using a delegation-based composite. 
**The `OAuth2AuthorizedClientProviderBuilder` may be used to configure and build the delegation-based composite.**

REVIEW
- `ClientRegistration` is a representation of a client registered with an OAuth 2.0 or OpenID Connect 1.0 Provider.
- `OAuth2AuthorizedClient` is a representation of an Authorized Client.
   > So A Oauth2 Authorized provider must provider these two 

The following Code shows how to build custom Oauth2user Authorization
```java
@Bean
public OAuth2AuthorizedClientManager authorizedClientManager(
	/* Get Clinet Registration */
	ClientRegistrationRepository clientRegistrationRepository,
	/* Get Authrorized Client */
	OAuth2AuthorizedClientRepository authorizedClientRepository) {

	/* 
	* Building/Configuring A Custom Oauth2AuthroizedClientProvider 
	* Ask for the following information authorizationnCode, refreshToken, clientCredentials,   password ...
	*/
	OAuth2AuthorizedClientProvider authorizedClientProvider =
	    OAuth2AuthorizedClientProviderBuilder.builder()
		    .authorizationCode()
		    .refreshToken()
		    .clientCredentials()
		    .password()
		    .build();

	// Set up the ClientManager with A the custom Provider 
	DefaultOAuth2AuthorizedClientManager authorizedClientManager =
	    new DefaultOAuth2AuthorizedClientManager(clientRegistrationRepository, authorizedClientRepository);
	// The construction of Provider is based on clientRegistrationRepository and authorizedClinetRepository
	authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

	return authorizedClientManager;
}
```

## set up contextAttributeMapper for OAuth2AuthorizedClientManager

If we need the `OAuth2AuthorizedClientProvider` requires the (end user) resource owner’s username and password to be available in `OAuth2AuthorizationContext.getAttributes().`
- We must set up out `setAuthorizedAttributesMapper(...)` in instance of authroziedClientManager
```java
@Bean
public OAuth2AuthorizedClientManager authorizedClientManager(
        ClientRegistrationRepository clientRegistrationRepository,
        OAuth2AuthorizedClientRepository authorizedClientRepository) {
    
    OAuth2AuthorizedClientProvider authorizedClientProvider =
            OAuth2AuthorizedClientProviderBuilder.builder()
                    .password()
                    .refreshToken()
                    .build();

    DefaultOAuth2AuthorizedClientManager authorizedClientManager =
            new DefaultOAuth2AuthorizedClientManager(clientRegistrationRepository, authorizedClientRepository);
    
    authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

    // 1. Assuming the `username` and `password` are supplied as `HttpServletRequest` parameters,
    // 2. The Instance of DefaultOAuth2AuthorizedClientManager is designed to be used within the context of a HttpServletRequest. 
    authorizedClientManager.setContextAttributesMapper(contextAttributesMapper());

    return authorizedClientManager;
}

private Function<OAuth2AuthorizeRequest, Map<String, Object>> contextAttributesMapper() {
    return authorizeRequest -> {
        Map<String, Object> contextAttributes = Collections.emptyMap();
        HttpServletRequest servletRequest = authorizeRequest.getAttribute(HttpServletRequest.class.getName());
	
	// We get username and password from request
        String username = servletRequest.getParameter(OAuth2ParameterNames.USERNAME);
        String password = servletRequest.getParameter(OAuth2ParameterNames.PASSWORD);

        if (StringUtils.hasText(username) && StringUtils.hasText(password)) {
            contextAttributes = new HashMap<>();
            // `PasswordOAuth2AuthorizedClientProvider` requires both attributes
            contextAttributes.put(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, username);
            contextAttributes.put(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, password);
        }
        return contextAttributes;
    };
}   
```
- When operating outside of a HttpServletRequest context(e.g loads clientRegistrationId, principal name ...etc), use AuthorizedClientServiceOAuth2AuthorizedClientManager instead. [Difference btw them](https://stackoverflow.com/questions/67500742/what-is-the-difference-between-defaultoauth2authorizedclientmanager-and-authoriz)  

```java
@Bean
public OAuth2AuthorizedClientManager authorizedClientManager(
        ClientRegistrationRepository clientRegistrationRepository,
        OAuth2AuthorizedClientService authorizedClientService) {

    /* Authenticate with attributes in client registration
       not from HttpServletRequest (e.g. password , username , token ... etc)
    */
    OAuth2AuthorizedClientProvider authorizedClientProvider =
            OAuth2AuthorizedClientProviderBuilder.builder()
                    .clientCredentials()
                    .build();
		    
    /* here we use ServiceOAuth2AuthorizedClientManager */
    AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientManager =
            new AuthorizedClientServiceOAuth2AuthorizedClientManager(
                    clientRegistrationRepository, authorizedClientService);
    authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

    return authorizedClientManager;
}
```

## Oauth2 User filter

## OAuth2AuthorizationRequestRedirectFilter 

OAuth2AuthorizationRequestRedirectFilter的作用就是上面步骤中的1.2步的合体，当用户点击页面的github授权url之后，
OAuth2AuthorizationRequestRedirectFilter匹配这个请求，接着它会将我们配置文件中的clientId、scope以及构造一个state参数（防止csrf攻击）拼接成一个url重定向到github的授权url，

OAuth2LoginAuthenticationFilter的作用则是上面3.4步骤的合体，
当用户在github的授权页面授权之后github调用回调地址，OAuth2LoginAuthenticationFilter匹配这个回调地址，解析回调地址后的code与state参数进行验证之后内部拿着这个code远程调用github的access_token地址，拿到access_token之后通过OAuth2UserService获取相应的用户信息（内部是拿access_token远程调用github的用户信息端点）最后将用户信息构造成Authentication被SecurityContextPersistenceFilter过滤器保存到HttpSession中。

[Oauth2 Filter Code](https://www.gushiciku.cn/pl/pnSK/zh-/tw)  

`The OAuth2AuthorizationRequestRedirectFilter` uses an `OAuth2AuthorizationRequestResolver` to resolve an `OAuth2AuthorizationRequest` and **initiate the Authorization Code grant flow by redirecting the end-user’s user-agent to the Authorization Server’s Authorization Endpoint**.  
> The default implementation `DefaultOAuth2AuthorizationRequestResolver` matches on the (default) path `/oauth2/authorization/{registrationId}` extracting the `registrationId` (from class ClientRegistration is a representation of a client registered with an OAuth 2.0 or OpenID Connect 1.0 Provider.)
 and using it to build the `OAuth2AuthorizationRequest` for the associated ClientRegistration.  
> `DefaultOAuth2AuthorizationRequestResolver` determines to give a grant or not and then return instance of the `AuthorizaionRequest` to filter.  
```java
public class OAuth2AuthorizationRequestRedirectFilter extends OncePerRequestFilter {
    
  //...

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {

    try {
      // generate a Oauth2AtuhroizationRequest
      OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestResolver.resolve(request);
      if (authorizationRequest != null) {
        // Authorized EndPoint
        this.sendRedirectForAuthorization(request, response, authorizationRequest);
        return;
      }
    } catch (Exception failed) {
      this.unsuccessfulRedirectForAuthorization(request, response, failed);
      return;
    }
    //...
}

private void sendRedirectForAuthorization(HttpServletRequest request, HttpServletResponse response,
                                          OAuth2AuthorizationRequest authorizationRequest) throws IOException {

    if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationRequest.getGrantType())) {
        this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, request, response);
    }
    this.authorizationRedirectStrategy.sendRedirect(request, response, authorizationRequest.getAuthorizationRequestUri());
}
```


If the grant is valid then we goes the next filter `OAuth2LoginAuthenticationFilter`  
it checks the token that client gives via `OAuth2LoginAuthenticationProvider` then get protected resouce if token is authenticated.

## AuthorizationRequestRepository (Authorization EndPoint)
The `AuthorizationRequestRepository` is responsible for the persistence of the `OAuth2AuthorizationRequest` from the time the Authorization Request is initiated to the time the Authorization Response is received (the callback).

It is Used by the` OAuth2AuthorizationRequestRedirectFilter` for persisting the Authorization Request before it initiates the authorization code grant flow.  
As well, used by the OAuth2LoginAuthenticationFilter for resolving the associated Authorization Request when handling the callback of the Authorization Response.

- OAuth2AuhroizationRequest
 > A representation of an OAuth 2.0 Authorization Request for the authorization code grant type or implicit grant type.
 > [code](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/oauth2/core/endpoint/OAuth2AuthorizationRequest.html)
A custom AuthorizationRequestRepository
```java
@EnableWebSecurity
public class OAuth2ClientSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .oauth2Client(oauth2Client ->
                oauth2Client
                    .authorizationCodeGrant(authorizationCodeGrant ->
                        authorizationCodeGrant
                            .authorizationRequestRepository(this.authorizationRequestRepository())
                            ...
                    )
            );
    }
}
```


Oauth2User has defaultprovider called `CommonOAuth2Provider` to fetch protected resource from google, github, facebook 
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

  private static final String DEFAULT_REDIRECT_URL = "{baseUrl}/{action}/oauth2/code/{registrationId}";

  protected final ClientRegistration.Builder getBuilder(String registrationId,
                              ClientAuthenticationMethod method, String redirectUri) {
    ClientRegistration.Builder builder = ClientRegistration.withRegistrationId(registrationId);
    builder.clientAuthenticationMethod(method);
    builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
    builder.redirectUriTemplate(redirectUri);
    return builder;
  }
    
  public abstract ClientRegistration.Builder getBuilder(String registrationId);
```




## Oauth2 Authentication Introspecter

It decodes String tokens into validated instances of `OAuth2AuthenticatedPrincipal`

The deafult QpaueTokenIntrospector and expose as a bean to be injected
```java
@Bean
public OpaqueTokenIntrospector introspector() {
    return new NimbusOpaqueTokenIntrospector(introspectionUri, clientId, clientSecret);
}
```

Or creating a custom introspector 

For example extracting Authorities Manually ...
```java
public class CustomAuthoritiesOpaqueTokenIntrospector implements OpaqueTokenIntrospector {
    private OpaqueTokenIntrospector delegate =
            new NimbusOpaqueTokenIntrospector("https://idp.example.org/introspect", "client", "secret");

    public OAuth2AuthenticatedPrincipal introspect(String token) {
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

then expose as bean
```java
@Bean
public OpaqueTokenIntrospector introspector() {
    return new CustomAuthoritiesOpaqueTokenIntrospector();
}
```

A custom introspector can 
- use `RestOperations` to cinfiguring timeout
- create custom JWTOpaueTokenIntrospector by implementing OpaqueTokenIntrospector

# OAuth 2.0 Login Custom  Configuration
```java
@EnableWebSecurity
public class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.oauth2Login()
				.authorizationEndpoint() /*login pager*/
					//...
				.redirectionEndpoint()
					//...
				.tokenEndpoint()
					//...
				.userInfoEndpoint()
					//...
	}
}
```

The authorization process utilizes two authorization server endpoints (HTTP resources): 
- Authorization Endpoint: **Used by the client** to obtain authorization from the resource owner via user-agent redirection. 
- Token Endpoint: **Used by the client** to exchange an authorization grant for an access token, typically with client authentication. 
- Redirection Endpoint: **Used by the authorization** server to return responses containing authorization credentials to the client via the resource owner user-agent. 
- The UserInfo Endpoint : is an OAuth 2.0 Protected Resource that returns claims about the authenticated end-user (**Instance of Authentication**). 
  > The client makes a request to the UserInfo Endpoint by using an access token obtained through OpenID Connect Authentication (Authorization Server). 
  > These claims are normally represented by a JSON object that contains a collection of name-value pairs for the claims.

## Customizing Login Page

To override the default login page, configure oauth2Login().loginPage() and (optionally) oauth2Login().authorizationEndpoint().baseUri().
```java
@Override
protected void configure(HttpSecurity http) throws Exception {
	http
		.oauth2Login()
			.loginPage("/login/oauth2")
			//...
			.authorizationEndpoint()
				.baseUri("/login/oauth2/authorization")
				//....
}
```
- Need to provide a `@Controller` with a `@RequestMapping("/login/oauth2")` that is capable of rendering the custom login page.
- Configuring `oauth2Login().authorizationEndpoint().baseUri()` is optional. However, if you choose to customize it, ensure the link to each OAuth Client matches the `authorizationEndpoint().baseUri()`.



## redirectionEndpoint

The Redirection Endpoint is used by the Authorization Server for returning the Authorization Response (which contains the authorization credentials) to the client

The default Authorization Response baseUri
```json
/login/oauth2/code/*
```

We can customize it to any other URL of our choice`(/oauth2/callback/)`.  
In application.properties
```json
spring.security.oauth2.client.registration.google.redirect-uri=http://localhost:8080/oauth2/callback/google
```
In Spring boot web security  
```java
protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().anyRequest().authenticated()
                .and()
                .oauth2Login()
                .redirectionEndpoint()
                 .baseUri("login/oauth2/callback/*");
    }
```

## userInfoEndpoint

It retrieve the authenticated Oauth2 User 

The UserInfo Endpoint includes a number of configuration options,
- Mapping Authenticated User from third party Authorities for this application
- “Configuring a Custom OAuth2User”
- “OAuth 2.0 UserService”
- “OpenID Connect 1.0 UserService”
```java
@Override
	protected void configure(HttpSecurity http) throws Exception {
		htt.oauth2Login()
		   .userInfoEndpoint()
		   // set up the Auhorities of this application
          	   .userAuthoritiesMapper(this.userAuthoritiesMapper())
		   // retrieve the authentticated user from third party
                   .userService(this.oauth2UserService())
		   .oidcUserService(this.oidcUserService())
	}
```


### configure a custom `.userAuthoritiesMapper(this.userAuthoritiesMapper)`

After the user successfully authenticates with the OAuth 2.0 Provider, the OAuth2User.getAuthorities() (or OidcUser.getAuthorities()) may be mapped to a new set of GrantedAuthority instances, which will be supplied to OAuth2AuthenticationToken when completing the authentication.
```java
	private GrantedAuthoritiesMapper userAuthoritiesMapper() {
		return (authorities) -> {
			Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

			authorities.forEach(authority -> {
				if (OidcUserAuthority.class.isInstance(authority)) {
					OidcUserAuthority oidcUserAuthority = (OidcUserAuthority)authority;

					OidcIdToken idToken = oidcUserAuthority.getIdToken();
					OidcUserInfo userInfo = oidcUserAuthority.getUserInfo();

					// Map the claims found in idToken and/or userInfo
					// to one or more GrantedAuthority's and add it to mappedAuthorities

				} else if (OAuth2UserAuthority.class.isInstance(authority)) {
					OAuth2UserAuthority oauth2UserAuthority = (OAuth2UserAuthority)authority;
          
					Map<String, Object> userAttributes = oauth2UserAuthority.getAttributes();

					// Map the attributes found in userAttributes
					// to one or more GrantedAuthority's and add it to mappedAuthorities

				}
			});

			return mappedAuthorities;
		};
	} 
```

### Configure a custom`.userService(this.oauth2UserService())` or `.oidcUserService(this.oidcUserService())`

The OAuth2UserRequest (and OidcUserRequest) provides you access to the associated OAuth2AccessToken, which is very useful in the cases where the delegator needs to fetch authority information from a protected resource before it can map the custom authorities for the user.

```java

	private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
		final OidcUserService delegate = new OidcUserService();

		return (userRequest) -> {
			// Delegate to the default implementation for loading a user
			OidcUser oidcUser = delegate.loadUser(userRequest);

			OAuth2AccessToken accessToken = userRequest.getAccessToken();
			Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

			// TODO
			// 1) Fetch the authority information from the protected resource using accessToken
			// 2) Map the authority information to one or more GrantedAuthority's and add it to mappedAuthorities

			// 3) Create a copy of oidcUser but use the mappedAuthorities instead
			oidcUser = new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());

			return oidcUser;
		};
	}
```

### Configure a `.customUserType(GitHubOAuth2User.class, "github")`

If the default implementation (DefaultOAuth2User) does not suit your needs, you can define your own implementation of OAuth2User.

for example creating a custom Oauth2User user Model for github
```java
@Override
protected void configure(HttpSecurity http) throws Exception {
	http
		.oauth2Login()
			.userInfoEndpoint()
				.customUserType(GitHubOAuth2User.class, "github")
				...
}
```

```java
public class GitHubOAuth2User implements OAuth2User {

  /* We often override getAuthorities() and getAttributes()*/
	private List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
	
  private Map<String, Object> attributes;
	private String id;
	private String name;
	private String login;
	private String email;

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return this.authorities;
	}

	@Override
	public Map<String, Object> getAttributes() {
		if (this.attributes == null) {
			this.attributes = new HashMap<>();
			this.attributes.put("id", this.getId());
			this.attributes.put("name", this.getName());
			this.attributes.put("login", this.getLogin());
			this.attributes.put("email", this.getEmail());
		}
		return attributes;
	}
  // getter and setter
}
```

### Configure a custom `.userService(this.oauth2Service())`

A `DefaultOAuth2UserService` is an implementation of an `OAuth2UserService` that supports standard OAuth 2.0 Provider’s.
> OAuth2UserService obtains the user attributes of the end-user (the resource owner) from the UserInfo Endpoint (by using the access token granted to the client during the authorization flow) and returns an AuthenticatedPrincipal in the form of an OAuth2User.


```java
//...
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.oauth2Login()
				.userInfoEndpoint()
					.userService(this.oauth2UserService())
					...
	}

	private OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {
		return new CustomOAuth2UserService();
  }
```


```java
@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService{

  @Autowired
  private UserRepository userRepository;
  //..

  @Override
  public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {
    //..

  
  }
}
```

# Customizing Token Endpoint

`OAuth2AccessTokenResponseClient` is responsible for exchanging an authorization grant credential for an access token credential at the Authorization Server’s Token Endpoint.

```java
@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.oauth2Login()
		    .tokenEndpoint()
		    	.accessTokenResponseClient(this.accessTokenResponseClient())
	             //...
	}

	private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
		return new SpringWebClientAuthorizationCodeTokenResponseClient();
	}
```
