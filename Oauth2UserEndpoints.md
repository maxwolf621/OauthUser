[More Details](https://datatracker.ietf.org/doc/html/rfc6749#section-1.1)  
[Good Explanation](http://www.ruanyifeng.com/blog/2019/04/oauth-grant-types.html)  
[Google API loging SetUp](https://xenby.com/b/245-%E6%95%99%E5%AD%B8-google-oauth-2-0-%E7%94%B3%E8%AB%8B%E8%88%87%E4%BD%BF%E7%94%A8%E6%8C%87%E5%8D%97)  
[The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)  

## Endpoints
![image](https://user-images.githubusercontent.com/68631186/122627719-db47c700-d0e3-11eb-9c9b-9c8f3743c623.png)
- Authorization Endpoint作為Authorization Server發行Authorization Grant
- Redirection Endpoint作為Client接收Authorization Grant
- Token Endpoint作為Authorization Server發行Access Token



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
- (C) Assuming the resource owner grants access, the authorization server redirects the user-agent back to the client using the `redirection URI` provided earlier (in the request or during client registration).  
     - The redirection URI includes an authorization code and any local state provided by the client earlier
     - accounts.google.com/o/oauth2/v2/auth?`response_type`=code&`client_id`=150677252870-78tlj6v2mm653alhodqr9t5br5fu5bs0.apps.googleusercontent.com&`scope`=openid+profile+email&`state`=QFWkpSxvN-zs5gGoMCnFGDJDTYF1HZg1FC_5l31H0qg%3D&`redirect_uri`=http%3A%2F%2Flocalhost%3A8080%2Flogin%2Foauth2%2Fcode%2Fgoogle.
- (D) The client requests an access token from the authorization server's token endpoint by including the authorization code received in the previous step. When making the request, the client authenticates with the authorization server. The client includes the redirection URI used to obtain the authorization code for verification.  
- (E) The authorization server authenticates the client, validates the authorization code, and ensures that the redirection URI received matches the URI used to redirect the client in step (C). **If valid, the authorization server responds back with an access token and, optionally, a refresh token.**  

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
                .authorizationCodeGrant()用户登入授权后，github调用我们应用的回调地址（我们刚刚注册github应用时填写的回调地址） 第三步的回调地址中github会将code参数放到url中，

接下来我们的客户端就会在内部拿这个code再次去调用github的access_token地址获取令牌

OAuth2AuthorizationRequestRedirectFilter handles for
                    .authorizationRequestRepository(this.authorizationRequestRepository())
                    .authorizationRequestResolver(this.authorizationRequestResolver())
                    .accessTokenResponseClient(this.accessTokenResponseClient());
    }
}
```
## Client Registration
We can configure client registration via java configuration or application.properties 

A client registration holds these information
```
client id
client secret
authorization grant type
redirect URI
scope(s)
authorization URI
token URI
```
and other details

### ClientRegistrationRepository
For compate with client registration from client.  
This repository provides the ability to retrieve a sub-set of the primary client registration information, which is stored with the Authorization Server.
> Spring Boot 2.x auto-configuration binds each of the properties under `spring.security.oauth2.client.registration.[registrationId]` to an instance of ClientRegistration and then composes each of the `ClientRegistration` instance(s) within a `ClientRegistrationRepository`. 

IF FRAMEWORK IS NOT SPRING BOOT THEN WE MUST DEFINE A `ClientRegistrationRepository` bean  
[EXAMPLE CODE HERE](https://www.baeldung.com/spring-security-5-oauth2-login)  
```java
@Controller
public class OAuth2ClientController {
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

## `OAuth2AuthorizedClientProvider`

A strategy for authorizing (or re-authorizing) an OAuth 2.0 Client 

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
   > For an Oauth2 Authorized provider must provide these two to authenticate

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

## set up `contextAttributeMapper` for custom `OAuth2AuthorizedClientManager`

If we need the `OAuth2AuthorizedClientProvider` requires the (end user) resource owner’s username and password to be available in `OAuth2AuthorizationContext.getAttributes().`

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
- When operating data outside of a HttpServletRequest context(e.g clientRegistrationId, principal name ...etc), use `AuthorizedClientServiceOAuth2AuthorizedClientManager` instead.  
- [AuthorizedClientServiceOAuth2AuthorizedClientManager and DefaultOAuth2AuthorizedClientManager](https://stackoverflow.com/questions/67500742/what-is-the-difference-between-defaultoauth2authorizedclientmanager-and-authoriz)  

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

# Oauth2 User Filter

There are two important filters
1. Oauth2AuthorizationRequestRedirectFilter (If the grant is valid then we goes the next filter `OAuth2LoginAuthenticationFilter`)
2. Oauth2LoginAuthenticationFilter

OAuth2AuthorizationRequestRedirectFilter handles for 
1. The user clicks *login via third party button* in the cient/application to redirect the user to third parhat the client request provided ty login page 
2. The user enters email and password etc in the third party page

> When user clicks login/sign up by third party (e.g github), then OAuth2AuthorizationRequestRedirectFilter will resolve this request.
> The request contains `client_id`、`scope` and `state` to form a `redirect_url` and redirect to third party authorized's url (github登入頁面)

OAuth2LoginAuthenticationFilter handles for
1. The filter will compare the data after the user press the login button in the third party page
2. (if the user is granted) filter will add `granted code` in the `redirect_url` 
3. parse the redirect_url' `granted code` and `state` with the ones stored in the http session if it is valid then it returns access_token url (so client can use this acces token to access third party resource)

> Oauth2LoginAuthenticationFilter check the grant code and state if they are valid then it return access_token
> client use access token and Iauth2UserService to get third party user details (protected resource ) and then return instance of Authenttication 
> After that SecurityContextPersistenceFilter will store protected resource store local http session  (local endpoint)

## OAuth2AuthorizationRequestRedirectFilter 
[Oauth2 Filter Code](https://www.gushiciku.cn/pl/pnSK/zh-/tw)  

The `OAuth2AuthorizationRequestRedirectFilter` uses 
1. an `OAuth2AuthorizationRequestResolver` to resolve an `OAuth2AuthorizationRequest` 
2. and **initiate the Authorization Code grant flow by redirecting the end-user’s user-agent to the Authorization Server’s Authorization Endpoint**.

```java
public class OAuth2AuthorizationRequestRedirectFilter extends OncePerRequestFilter {
  //...
  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
    try {
      //  resolve an Oauth2AuthorizationRequest
      OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestResolver.resolve(request);
      if (authorizationRequest != null) {
        // Initiate Redirct URL
        this.sendRedirectForAuthorization(request, response, authorizationRequest);
        return;
      }
    } catch (Exception failed) {
      this.unsuccessfulRedirectForAuthorization(request, response, failed);
      return;
    }
    //...
}
```
If the grant is valid then we goes the next filter `OAuth2LoginAuthenticationFilter`  

### Resolver

The default implementation `DefaultOAuth2AuthorizationRequestResolver` matches on the (default) path `/oauth2/authorization/{registrationId}` extracting the `registrationId` (from class `ClientRegistration`) and using it to build the `OAuth2AuthorizationRequest` for the associated ClientRegistration.  

`DefaultOAuth2AuthorizationRequestResolver` determines to give a grant or not and then return instance of the `AuthorizaionRequest` to filter.  
```java
OAuth2AuthorizationRequest resolve(javax.servlet.http.HttpServletRequest request)	
//Returns the OAuth2AuthorizationRequest resolved from the provided HttpServletRequest or null if not available.

OAuth2AuthorizationRequest resolve(javax.servlet.http.HttpServletRequest request, java.lang.String registrationId)	
//Returns the OAuth2AuthorizationRequest resolved from the provided HttpServletRequest or null if not available.

void setAuthorizationRequestCustomizer(java.util.function.Consumer<OAuth2AuthorizationRequest.Builder> authorizationRequestCustomizer)	
//Sets the Consumer to be provided the OAuth2AuthorizationRequest.Builder allowing for further customizations.

//...
private OAuth2AuthorizationRequest resolve(HttpServletRequest request, String registrationId,
		String redirectUriAction) {
	if (registrationId == null) {
		return null;
	}
	// get the associated registrationId from End User
	ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
	if (clientRegistration == null) {
		throw new IllegalArgumentException("Invalid Client Registration with Id: " + registrationId);
	}
	
	Map<String, Object> attributes = new HashMap<>();
	attributes.put(OAuth2ParameterNames.REGISTRATION_ID, clientRegistration.getRegistrationId());
	OAuth2AuthorizationRequest.Builder builder = getBuilder(clientRegistration, attributes);

	String redirectUriStr = expandRedirectUri(request, clientRegistration, redirectUriAction);

	// @formatter:off
	// Build up a OAuth2AuthorizationRequest 
	builder.clientId(clientRegistration.getClientId())
			.authorizationUri(clientRegistration.getProviderDetails().getAuthorizationUri())
			.redirectUri(redirectUriStr)
			.scopes(clientRegistration.getScopes())
			.state(this.stateGenerator.generateKey())
			.attributes(attributes);
	
	// @formatter:on
	this.authorizationRequestCustomizer.accept(builder);

	return builder.build();
}

/**
 * Expands the {@link ClientRegistration#getRedirectUri()} with following provided variables:
 * - baseUrl (e.g. https://localhost/app) 
 * - baseScheme (e.g. https) 
 * - baseHost (e.g. localhost) 
 * - basePort (e.g. :8080) 
 * - basePath (e.g. /app) 
 * - registrationId (e.g. google) 
 * - action (e.g. login) 
 ---------------------------------------------
 * Null variables are provided as empty strings.
 * Default redirectUri is:
 * {@code org.springframework.security.config.oauth2.client.CommonOAuth2Provider#DEFAULT_REDIRECT_URL}
 */
private static String expandRedirectUri(HttpServletRequest request, ClientRegistration clientRegistration,
		String action) {
	Map<String, String> uriVariables = new HashMap<>();
	
	
	uriVariables.put("registrationId", clientRegistration.getRegistrationId());
	
	// fromHttpUrl
	// @Code {UriComponents} 
	// https://github.com/spring-projects/spring-framework/blob/main/spring-web/src/main/java/org/springframework/web/util/UriComponentsBuilder.java
	UriComponents uriComponents = UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
			.replacePath(request.getContextPath())
			.replaceQuery(null)
			.fragment(null)
			.build();
	
	String scheme = uriComponents.getScheme();  // e.g. `https`
	uriVariables.put("baseScheme", (scheme != null) ? scheme : "");
	
	String host = uriComponents.getHost(); 
	uriVariables.put("baseHost", (host != null) ? host : "");
	
	int port = uriComponents.getPort();
	uriVariables.put("basePort", (port == -1) ? "" : ":" + port);
	
	String path = uriComponents.getPath();
	if (StringUtils.hasLength(path)) {
		if (path.charAt(0) != PATH_DELIMITER) {
			// "/" + path
			path = PATH_DELIMITER + path;
		}
	}
	uriVariables.put("basePath", (path != null) ? path : "");
	
	uriVariables.put("baseUrl", uriComponents.toUriString());
	
	uriVariables.put("action", (action != null) ? action : ""); // login , signup etc ...
	

	// RedirectUri : {baseScheme}://{baseHost}{basePort}{basePath}.
	return UriComponentsBuilder.fromUriString(clientRegistration.getRedirectUri())
			.buildAndExpand(uriVariables)
			.toUriString();
}
// ...
```

### Redirct URL

[forward and redirect](https://stackoverflow.com/questions/20371220/what-is-the-difference-between-response-sendredirect-and-request-getrequestdis)  

```java
private void sendRedirectForAuthorization(HttpServletRequest request, HttpServletResponse response,
                                          OAuth2AuthorizationRequest authorizationRequest) throws IOException {
    // check the Auhtorization Grant Type
    if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationRequest.getGrantType())) {
    	// save the request payloads (state, url ,... etc ) in http session
        this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, request, response);
    }
    // authorizationRedirectStrategy是DefaultRedirectStrategy
    this.authorizationRedirectStrategy.sendRedirect(request, response, authorizationRequest.getAuthorizationRequestUri());
}

public void sendRedirect(HttpServletRequest request, HttpServletResponse response,
                         String url) throws IOException {
    String redirectUrl = calculateRedirectUrl(request.getContextPath(), url);
    redirectUrl = response.encodeRedirectURL(redirectUrl);

    if (logger.isDebugEnabled()) {
        logger.debug("Redirecting to '" + redirectUrl + "'");
    }
 
    // the response will send here
    response.sendRedirect(redirectUrl);
}
```


## OAuth2LoginAuthenticationFilter

This filter
1. Process an Oauth 2.0 Authorization Response (by checking authorization code grant) 
2. Pass A Valid Access Token to `AuthenticationManager` to access the authenticated End-User details
3. Store the Authenticated User details from third party to local proected resource (session .. etc)

```java
/**
 * An implementation of an {@link AbstractAuthenticationProcessingFilter} for OAuth 2.0
 * Login.
 * This authentication {@code Filter} handles the processing of an OAuth 2.0 Authorization
 * Response for the authorization code grant flow and delegates an
 * {@link OAuth2LoginAuthenticationToken} to the {@link AuthenticationManager} to log in
 * the End-User.
 *
 /**********************Checking The Grant Code and State from Clinet***************************
 *The OAuth 2.0 Authorization Response is processed as follows:
 *     Assuming the End-User (Resource Owner) has granted access to the Client, 
 *    	the Authorization Server will append the {@link OAuth2ParameterNames#CODE code} and
 * 	{@link OAuth2ParameterNames#STATE state} parameters to the
 * 	{@link OAuth2ParameterNames#REDIRECT_URI redirect_uri} (provided in the Authorization Request) 
 *	and redirect the End-User's user-agent back to this {@code Filter} (the Client)
 *
 /***********************Generate the Token to client**************************************
 * This {@code Filter} will then create an {@link OAuth2LoginAuthenticationToken} with
 * 	the {@link OAuth2ParameterNames#CODE code} received 
 * 	and delegate it to the {@link AuthenticationManager} to authenticate.
 *
 /***********************For A Authenticated User who existing in third party protected resource*****
 * Upon a successful authentication, an {@link OAuth2AuthenticationToken} is created
 * 	(representing the End-User {@code Principal}) and associated to the
 * 	{@link OAuth2AuthorizedClient Authorized Client} using the
 * 	{@link OAuth2AuthorizedClientRepository}.
 *
 /***********************Save the this valid user principal into the local protected resource********
 * Finally, the {@link OAuth2AuthenticationToken} is returned and ultimately stored in
 * 	the {@link SecurityContextRepository} to complete the authentication processing.
 */
public class OAuth2LoginAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	// Default_url, assert_attributes ...
	
	private ClientRegistrationRepository clientRegistrationRepository;

	private OAuth2AuthorizedClientRepository authorizedClientRepository;

	private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository = new HttpSessionOAuth2AuthorizationRequestRepository();

        // ....
	
        @Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
			
		MultiValueMap<String, String> params = OAuth2AuthorizationResponseUtils.toMultiMap(request.getParameterMap());
		if (!OAuth2AuthorizationResponseUtils.isAuthorizationResponse(params)) {
			OAuth2Error oauth2Error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}
		
		// 
		OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestRepository
				.removeAuthorizationRequest(request, response);
		if (authorizationRequest == null) {
			OAuth2Error oauth2Error = new OAuth2Error(AUTHORIZATION_REQUEST_NOT_FOUND_ERROR_CODE);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}
		
		// Find the client via authroizartionRequest
		String registrationId = authorizationRequest.getAttribute(OAuth2ParameterNames.REGISTRATION_ID);
		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
		if (clientRegistration == null) {
			OAuth2Error oauth2Error = new OAuth2Error(CLIENT_REGISTRATION_NOT_FOUND_ERROR_CODE,
					"Client Registration not found with Id: " + registrationId, null);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}
		
		/**
		 *  Build an Access Token url
		*/
		// @formatter:off
		String redirectUri = UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
				.replaceQuery(null)
				.build()
				.toUriString();
				
		// @formatter:on
		OAuth2AuthorizationResponse authorizationResponse = OAuth2AuthorizationResponseUtils.convert(params,
				redirectUri);
		Object authenticationDetails = this.authenticationDetailsSource.buildDetails(request);
		
		// generate access token authenticationRequest
		OAuth2LoginAuthenticationToken authenticationRequest = new OAuth2LoginAuthenticationToken(clientRegistration,
				new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse));
		authenticationRequest.setDetails(authenticationDetails);
		
		// Make authenticationRequest authenticationRequest
		OAuth2LoginAuthenticationToken authenticationResult = (OAuth2LoginAuthenticationToken) this
				.getAuthenticationManager().authenticate(authenticationRequest);
				
		// 
		OAuth2AuthenticationToken oauth2Authentication = new OAuth2AuthenticationToken(
				authenticationResult.getPrincipal(), authenticationResult.getAuthorities(),
				authenticationResult.getClientRegistration().getRegistrationId());
		oauth2Authentication.setDetails(authenticationDetails);
		
		// create a new Oauth2authroizedCient and save it  
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
				authenticationResult.getClientRegistration(), oauth2Authentication.getName(),
				authenticationResult.getAccessToken(), authenticationResult.getRefreshToken());
		this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, oauth2Authentication, request, response);
		
		return oauth2Authentication;
	}
}
```

```java
public class OAuth2LoginAuthenticationProvider implements AuthenticationProvider {
    
    //...
    
    @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    OAuth2LoginAuthenticationToken authorizationCodeAuthentication =
      (OAuth2LoginAuthenticationToken) authentication;

   
    if (authorizationCodeAuthentication.getAuthorizationExchange()
      .getAuthorizationRequest().getScopes().contains("openid")) {
      
      
      return null;
    }

    OAuth2AccessTokenResponse accessTokenResponse;
    try {
      OAuth2AuthorizationExchangeValidator.validate(
          authorizationCodeAuthentication.getAuthorizationExchange());
      
      accessTokenResponse = this.accessTokenResponseClient.getTokenResponse(
          new OAuth2AuthorizationCodeGrantRequest(
              authorizationCodeAuthentication.getClientRegistration(),
              authorizationCodeAuthentication.getAuthorizationExchange()));

    } catch (OAuth2AuthorizationException ex) {
      OAuth2Error oauth2Error = ex.getError();
      throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
    }
    
         
    OAuth2AccessToken accessToken = accessTokenResponse.getAccessToken();
    Map<String, Object> additionalParameters = accessTokenResponse.getAdditionalParameters();
    
         
    OAuth2User oauth2User = this.userService.loadUser(new OAuth2UserRequest(
        authorizationCodeAuthentication.getClientRegistration(), accessToken, additionalParameters));

    Collection<? extends GrantedAuthority> mappedAuthorities =
      this.authoritiesMapper.mapAuthorities(oauth2User.getAuthorities());
    
         
    OAuth2LoginAuthenticationToken authenticationResult = new OAuth2LoginAuthenticationToken(
      authorizationCodeAuthentication.getClientRegistration(),
      authorizationCodeAuthentication.getAuthorizationExchange(),
      oauth2User,
      mappedAuthorities,
      accessToken,
      accessTokenResponse.getRefreshToken());
    authenticationResult.setDetails(authorizationCodeAuthentication.getDetails());

    return authenticationResult;
  }
    ...省略部分代码
}

```
OAuth2LoginAuthenticationProvider的执行逻辑很简单，首先通过code获取access_token，然后通过access_token获取用户信息，这和标准的oauth2授权码模式一致。


### Conclusion

1. OAuth2AuthorizationRequestResolver resolves the request from client，
   > If the request is not null, it returns an instance of OAuth2AuthorizationRequest including `client_id`, `state`, `redirect_uri`

2. Store this oAuth2AuthorizationRequest via `authorizationRequestRepository.saveAuthorizationRequest` in http session 
   > Authorization Server can look up authorization request's attribute `state` in the httpsession to compare wiht `state` from client's request to prevent the csrf attack

B. (if retured OAuth2AuthorizationRequest instance is not null)，response.sendRedirect OAuth2AuthorizationRequest's authorization endpoint request send to frontend's response payload to redirect browser to authorized page for the user entering password .. etc to be authenticated

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
