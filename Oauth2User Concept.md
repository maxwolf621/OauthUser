[More Details](https://datatracker.ietf.org/doc/html/rfc6749#section-1.1)
[Good Explanation](http://www.ruanyifeng.com/blog/2019/04/oauth-grant-types.html)
# Protocol Flow 

``````
 +--------+                               +---------------+
 |        |--(A)- Authorization Request ->|   Resource    |
 |        |                               |     Owner     |
 |        |<-(B)-- Authorization Grant ---|               |
 |        |                               +---------------+
 |        |
 |        |                               +---------------+
 |        |--(C)-- Authorization Grant -->| Authorization |
 | Client |                               |     Server    |
 |        |<-(D)----- Access Token -------|               |
 |        |                               +---------------+
 |        |
 |        |                               +---------------+
 |        |--(E)----- Access Token ------>|    Resource   |
 |        |                               |     Server    |
 |        |<-(F)--- Protected Resource ---|               |
 +--------+                               +---------------+
``````

1. Request For The Permission via ClientRegistrations (Model : AuthorizedClient)
    > Client Requests Resource Owner the Authorization Grant (A permission)

(If Resource Owner grants the Permission for the client)

2. Request For The Token via the grant (Model: OAuth2AuthorizationRequest)
    > The client requests an access token by authenticating with the authorization server and presenting the authorization grant.

(If the Grant is valid) 
3. Request For the Proteted Resource (e.g. User Detail Information) via the token
    > The client requests the protected resource from the resource server and authenticates by presenting the access token.


[More Details](https://blog.yorkxin.org/posts/oauth2-4-1-auth-code-grant-flow.html)
- Client gives a url to let Resource onwer redirect to Authorization Server to ask for permission

###  Authorization Grant and Access Code
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

(A). The client initiates the flow by directing the resource owner's user-agent to the authorization endpoint.  
     The client includes its client identifier, requested scope, local state, and a redirection URI to which the authorization server will send the user-agent back once access is granted (or denied).  
(B)  The authorization server authenticates the resource owner (via the user-agent) and establishes whether the resource owner grants or denies the client's access request.  

(C)  Assuming the resource owner grants access, the authorization server redirects the user-agent back to the client using the `redirection URI` provided earlier (in the request or during client registration).  
     - The redirection URI includes an authorization code and any local state provided by the client earlier.

(D). The client requests an access token from the authorization server's token endpoint by including the authorization code received in the previous step.  
     When making the request, the client authenticates with the authorization server.  
     The client includes the redirection URI used to obtain the authorization code for verification.  
(E). The authorization server authenticates the client, validates the authorization code, and ensures that the redirection URI received matches the URI used to redirect the client in step (C).   
     If valid, the authorization server responds back with an access token and, optionally, a refresh token.


An authorization grant is a credential representing the resource owner's authorization (to access its protected resources) used by the client to obtain an access token.  
This specification defines four grant types
1. authorization code
2. implicit其中 client_id 只有 Public Client 才需要提供，如果是 Confidential Client 或有拿到 Client Credentials ，就必須進行 Client 認證
3. resource owner password credentials
4. client credentials 

[ref](https://blog.yorkxin.org/posts/oauth2-4-1-auth-code-grant-flow.html)

(A). Client sends request to Resource Owner via User Agent  
Request includes
- Client ID
- 申請的 scopes
- 內部 state
- Redirection URI，申請結果下來之後 Authorization Server 要轉址過去。

(B). Authorization Server identifies/authorizes the grant of This `Resource Owner` via User-Agent  
```json
accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=150677252870-78tlj6v2mm653alhodqr9t5br5fu5bs0.apps.googleusercontent.com&scope=openid+profile+email&state=QFWkpSxvN-zs5gGoMCnFGDJDTYF1HZg1FC_5l31H0qg%3D&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Flogin%2Foauth2%2Fcode%2Fgoogle.
```


(C). If Resource Owner is **granted** to access ， Authorization Server redirect the User-Agent baack to Redirection URI (that client provided)
The URI includes
- Authorization Code
- 許可的 scopes （如果跟申請的不一樣才會附上）
- 先前提供的內部 state （原封不動，如果先前有提供才會附上）

(D). Client 向 Authorization Server 的 Token Endpoint 要求 Access Token，申請時會傳送
- Valid Authorization Code(Authorization Server must compare this with its)
- Redirection URI，用來驗證和之前 (C) 時的一致。
- Client 的認證資料

(E). Authorization Server 認證 Client 、驗證 Authorization Code、並確認 Redirection URI 和之前 (C) 轉址的一致。都符合的話，Authorization Server 會回傳 Access Token ，以及可選的 Refresh Token。


# Oauth2User Authentication Flow

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

We can configure client registration via java configuration or application.properties 

### ClientRegistration

A client registration holds information, such as client id, client secret, authorization grant type, redirect URI, scope(s), authorization URI, token URI, and other details.

### ClientRegistrationRepository

- This repository provides the ability to retrieve a sub-set of the primary client registration information, which is stored with the Authorization Server.

> Spring Boot 2.x auto-configuration binds each of the properties under `spring.security.oauth2.client.registration.[registrationId]` to an instance of ClientRegistration and then composes each of the `ClientRegistration` instance(s) within a `ClientRegistrationRepository`.

IF FRAMEWORK IS NOT SPRING BOOT THEN WE MUST DEFINE A `ClientRegistrationRepository` bean [EXAMPLE CODE HERE](https://www.baeldung.com/spring-security-5-oauth2-login)

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

# To get The Permission(Access Token) to access the protectd resource
- Do Authentication via `OAuth2AuthorizedClientProvider`
- Delegating the persistence of an `OAuth2AuthorizedClient`, typically using an `OAuth2AuthorizedClientService` and `OAuth2AuthorizedClientRepository` provide lookup associated with the `clientOAuth2AccessToken`

[](https://www.programmersought.com/article/10451235590/)  

For such purpose we need these 
- Model
  > Oauth2AuthorizedClient
- Repository
  > OAuth2AuthorizedClientRepository
- Service
  > OAuth2AuthorizedClientService

### OAuth2AuthorizedClient 
- A client is considered to be authorized when the end-user (Resource Owner) has granted authorization to the client to access its protected resources.
  > In short it will store the authenticated access Token, who is the authenticated client … etc  
[Code of OAuth2AuthrizedClient](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/oauth2/client/OAuth2AuthorizedClient.html)

### Build up a Custom OAuth2 Provider for Oauth2 AuthenticationManager

An `OAuth2AuthorizedClientProvider` implements a strategy(pattern) for authorizing (or re-authorizing) an OAuth 2.0 Client. 
- Implementations will typically implement an authorization grant type, eg. authorization_code, client_credentials, userInfoEndpoint

The default implementation of `OAuth2AuthorizedClientManager` is `DefaultOAuth2AuthorizedClientManager`, which is associated with an `OAuth2AuthorizedClientProvider` that may support multiple authorization grant types using a delegation-based composite. 
  > The `OAuth2AuthorizedClientProviderBuilder` may be used to configure and build the delegation-based composite.

The following Code shows how to build Authentication provider and ste up Authentication Manager 
```java
/* To build a custom provider via strategy pattern */
@Bean
public OAuth2AuthorizedClientManager authorizedClientManager(
        /* Get Permission */
        ClientRegistrationRepository clientRegistrationRepository,
        /* Get Protected Resoruce */
        OAuth2AuthorizedClientRepository authorizedClientRepository) {

    // Building A Custom Oauth2AuthroizedClientProvider 
    //  Ask for the following information authorizationnCode, refreshToken, clientCredentials,   password ...
    OAuth2AuthorizedClientProvider authorizedClientProvider =
            OAuth2AuthorizedClientProviderBuilder.builder()
                    .authorizationCode()
                    .refreshToken()
                    .clientCredentials()
                    .password()
                    .build();

    // Set up the ClientManager with A the custom Provider 
    DefaultOAuth2AuthorizedClientManager authorizedClientManager =
            new DefaultOAuth2AuthorizedClientManager(
                    clientRegistrationRepository, authorizedClientRepository);
    authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

    return authorizedClientManager;
}
```

## contextAttributeMapper

if the PasswordOAuth2AuthorizedClientProvider requires the resource owner’s username and password to be available in OAuth2AuthorizationContext.getAttributes().

We must set up out `setAuthorizedAttributesMapper(...)` in instance of authroziedClientManager
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
            new DefaultOAuth2AuthorizedClientManager(
                    clientRegistrationRepository, authorizedClientRepository);
    authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

    // Assuming the `username` and `password` are supplied as `HttpServletRequest` parameters,The DefaultOAuth2AuthorizedClientManager is designed to be used within the context of a HttpServletRequest. When operating outside of a HttpServletRequest context, use AuthorizedClientServiceOAuth2AuthorizedClientManager instead.


    // map the `HttpServletRequest` parameters to `OAuth2AuthorizationContext.getAttributes()`
    authorizedClientManager.setContextAttributesMapper(contextAttributesMapper());

    return authorizedClientManager;
}

private Function<OAuth2AuthorizeRequest, Map<String, Object>> contextAttributesMapper() {
    return authorizeRequest -> {
        Map<String, Object> contextAttributes = Collections.emptyMap();
        HttpServletRequest servletRequest = authorizeRequest.getAttribute(HttpServletRequest.class.getName());
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
The DefaultOAuth2AuthorizedClientManager is designed to be used within the context of a HttpServletRequest. 

When operating outside of a HttpServletRequest context(e.g loads clientRegistrationId, principal name ...etc), use AuthorizedClientServiceOAuth2AuthorizedClientManager instead.


[Difference](https://stackoverflow.com/questions/67500742/what-is-the-difference-between-defaultoauth2authorizedclientmanager-and-authoriz)

```java
@Bean
public OAuth2AuthorizedClientManager authorizedClientManager(
        ClientRegistrationRepository clientRegistrationRepository,
        OAuth2AuthorizedClientService authorizedClientService) {

    /* Authenticate with registrationId … 
       Not HttpServletRequest (e.g. password , username , token ... etc)
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

# To get the protected resource via token

## OAuth2AuthorizationRequestRedirectFilter 
- Check Valid of An Access Token

[Ref](https://www.gushiciku.cn/pl/pnSK/zh-/tw)

`The OAuth2AuthorizationRequestRedirectFilter` uses an `OAuth2AuthorizationRequestResolver` to resolve an `OAuth2AuthorizationRequest` and initiate the Authorization Code grant flow by redirecting the end-user’s user-agent to the Authorization Server’s Authorization Endpoint.

> The default implementation `DefaultOAuth2AuthorizationRequestResolver` matches on the (default) path `/oauth2/authorization/{registrationId}` extracting the `registrationId` and using it to build the `OAuth2AuthorizationRequest` for the associated ClientRegistration.

DefaultOAuth2AuthorizationRequestResolver determine to give a grant or not and then return instance of the `AuthorizaionRequest` to filter.

(A `AuthorizationRequest` includes ent_id, state, redirect_uri … etc)

After that we need to redirect to the endpoint and send access token to client

if the grant is valid then we goes the next filter `OAuth2LoginAuthenticationFilter`

it checks the token that client gives via `OAuth2LoginAuthenticationProvider` then get protected resouce if token is authenticated.

## Get A Token via AuthorizationRequestRepository

The `AuthorizationRequestRepository` is responsible for the persistence of the `OAuth2AuthorizationRequest` from the time the Authorization Request is initiated to the time the Authorization Response is received (the callback).

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

## Get A Protected Resource 

Oauth2User has default provider called `CommonOAuth2Provider` to fetch protected resource from google, github, facebook 
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



# OAuth 2.0 Login Configuration
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
- Authorization Endpoint: Used by the client to obtain authorization from the resource owner via user-agent redirection.
- Token Endpoint: Used by the client to exchange an authorization grant for an access token, typically with client authentication.


- Redirection Endpoint: Used by the authorization server to return responses containing authorization credentials to the client via the resource owner user-agent.
- The UserInfo Endpoint is an OAuth 2.0 Protected Resource that returns claims about the authenticated end-user. 
  > The client makes a request to the UserInfo Endpoint by using an access token obtained through OpenID Connect Authentication (Authorization Server). 
  > These claims are normally represented by a JSON object that contains a collection of name-value pairs for the claims.

# Customizing Login Page

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



# Customizing Spring Security oauth2Login()

The Redirection Endpoint is used by the Authorization Server for returning the Authorization Response (which contains the authorization credentials) to the client via the Resource Owner user-agent.


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

# Customizing userInfoEndpoint()

Our custom user info endpoint will make request to the provider user info endpoint and retrieve the user info such as name, email, image etc.

The UserInfo Endpoint includes a number of configuration options,
“Mapping User Authorities”
“Configuring a Custom OAuth2User”
“OAuth 2.0 UserService”
“OpenID Connect 1.0 UserService”
```java
@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.oauth2Login()
				.userInfoEndpoint()
          /* Options */
          .userAuthoritiesMapper(this.userAuthoritiesMapper())
          // or 
          .userService(this.oauth2UserService())
					// or 
          .oidcUserService(this.oidcUserService())
					...
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

### Configure a `..customUserType(GitHubOAuth2User.class, "github")`

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

OAuth2AccessTokenResponseClient is responsible for exchanging an authorization grant credential for an access token credential at the Authorization Server’s Token Endpoint.

```java
@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.oauth2Login()
				.tokenEndpoint()
					.accessTokenResponseClient(this.accessTokenResponseClient())
	        //...
	}

	private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
		return new SpringWebClientAuthorizationCodeTokenResponseClient();
	}
```