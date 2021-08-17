[More Details](https://datatracker.ietf.org/doc/html/rfc6749#section-1.1)  
[Good Explanation](http://www.ruanyifeng.com/blog/2019/04/oauth-grant-types.html)  
[Google API loging SetUp](https://xenby.com/b/245-%E6%95%99%E5%AD%B8-google-oauth-2-0-%E7%94%B3%E8%AB%8B%E8%88%87%E4%BD%BF%E7%94%A8%E6%8C%87%E5%8D%97)  
[The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)  
[Attributes of Different Third Parties](https://blog.yorkxin.org/posts/oauth2-implementation-differences-among-famous-sites.html)


## Basic Oauth2 User Login Flow via GITHUB
[How to Login](https://medium.com/swlh/spring-boot-oauth2-login-with-github-88b178e0c004)  
[code](https://github.com/maxwolf621/OauthUser/tree/main/demo)  

Oauth2 Client Setup in Maven  
```xml
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-oauth2-client</artifactId>
</dependency>
```

Add client registration details in application.properties
```diff
spring.security.oauth2.client.registration.github.client-id= ...
spring.security.oauth2.client.registration.github.client-secret= ...
spring.security.oauth2.client.registration.github.redirect-uri= ...
```

## Configure spring boot web security for OAuth2  

[Configure the authorization of the ROLE](https://stackoverflow.com/questions/36233910/custom-http-security-configuration-along-with-oauth2-resource-server)

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
Run `mvn spring boot:run`  
Now by accessing default host `localhost:8080` it will direct to the AuthorizedEndpoint (login page of the thrid party application) 

After the user entered the password and the email, it might have two results
1. It failed then it redirects to `http://localhost:8080/oauth2/authorization/github`

2. It successed then the request (sent by client) is getting handled by `OAuth2AuthorizationRequestRedirectFilter`
Internally, this , which uses implements doFilterInternal that matches against the `/oauth2/authorization/github` URI and redirect the request to
```http
https://github.com/login/oauth/authorize?response_type=code&client_id=<clientId>&scope=read:user&state=<state>&redirect_uri=http://localhost:8080/login/oauth2/code/github
```
- the above (redirected endpoint) `redirect_uri` contains the same value we put when we registered our `application.properties`.  

After the User successfully authenticates against GitHub, the user will be redirected to (default) `http://localhost:8080/login/oauth2/code/github` with the authentication code in the request parameters.  
This will be handled by the `OAuth2LoginAuthenticationFilter`, which will perform a POST request to the GitHub API to get an authentication token.


- 使用者訪問Client端之後，Client會將The User導向Provider，Provider向The User詢問是否對 Client 授權 
- 使用者同意授權後(同意授權的意思就是The USER成功登入第三方帳戶)，Provider向Client返回一個Authorization Code。
- Client再用Authorization Code申請Access Token
- Provider _Authenticates_ Authorization Code後responses _Access Token_
- Client sends Token Aces使用者在 Provider 上的資源


# Endpoints
![image](https://user-images.githubusercontent.com/68631186/122627719-db47c700-d0e3-11eb-9c9b-9c8f3743c623.png)
[Protocol Endpoints](https://datatracker.ietf.org/doc/html/rfc6749#section-3)  
- Authorization Endpoint(used by client)作為Authorization Server發行Authorization Grant (intercepted by OAuth2AuthorizationRequestRedirectFilter)
- Redirection Endpoint(used by authorization server)作為Client接收Authorization Grant   (intercepted by Login Authentication Filter)
- Token Endpoint作為Authorization Server發行Access Token



## How The User get third party application's protected Resource via Client
```
	     +----------+
	     | Resource |
	     |   Owner  |
	     +----------+
		  ^
		  |
		 (B)
		  |
	     +----|-----+          Client Identifier      +---------------+
	     |          |>---(A)-- & Redirection URI ---->|               |
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

[Ref](https://stackoverflow.com/questions/12482070/how-does-a-user-register-with-oauth)   
- Resource Owner (Your third party application Account)  
- Client app (The Application you are currently using)  
- Identity Provider (Third Party Application authenticates the identity : Google, Facebook, Twitter, etc...)  
- Resource Server (Third Party Application's Server, e.g. Authorization Server, Resource Server, etc ... )  
- Resources (Resource in third party application that you are trying to access via the client)  

[Auth Code Grant Flow](https://blog.yorkxin.org/posts/oauth2-4-1-auth-code-grant-flow.html) 
- (.) The User Accesses The Client ( The Application ) 
- (A) The client initiates the flow by directing the resource owner's **user-agent to the authorization endpoint**. 
	> The client includes its client identifier, requested `scope`, local `state`, and a `redirect_uri` to which the authorization server will send the user-agent back once the user granted (or denied) the access (to the third party account) via Client.  
- (B) The authorization server authenticates the resource owner (via the user-agent) and **establishes** whether the resource owner grants or denies the client's access request.  
- (C) Assuming the resource owner grants access, the authorization server redirects the user-agent back to the client using the `redirect_uri` provided earlier.  
     - The redirection URI includes an `authorization code` and any local `state` provided by the client earlier 
     > For example   
     >> accounts.google.com/o/oauth2/v2/auth?`response_type`=code&`client_id`=150677252870-78tlj6v2mm653alhodqr9t5br5fu5bs0.apps.googleusercontent.com&`scope`=openid+profile+email&`state`=QFWkpSxvN-zs5gGoMCnFGDJDTYF1HZg1FC_5l31H0qg%3D&`redirect_uri`=http%3A%2F%2Flocalhost%3A8080%2Flogin%2Foauth2%2Fcode%2Fgoogle.
- (D) The client requests an access token from the authorization server's token endpoint by including the authorization code received in the previous step. 
- (E) The authorization server authenticates the client, validates the authorization code, and ensures that the redirection URI received matches the URI used to redirect the client in step (C). **If valid, the authorization server responds back with an access token and, optionally, a refresh token.**  

# Configure The OAuth2 Client

To define the Client ( The Application ) have the authorization to fetch the protected resource from the third party application
```java
@EnableWebSecurity
public class OAuth2ClientSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .oauth2Client()
                .clientRegistrationRepository(this.clientRegistrationRepository())
                .authorizedClientRepository(this.authorizedClientRepository())
                .authorizedClientService(this.authorizedClientService())
                .authorizationCodeGrant()
    }
}
```
## (INFORMATION) Client Registration
- We can configure client registration via `java configuration` or `application.properties`  

A client registration holds these (The Most Important) information  
```
client id 	
client secret
authorization grant type 
scope(s) 

redirect URI 
authorization URI
token URI
```

## (GET CLIENT REGISTRAION INFORMATION) ClientRegistrationRepository
**This repository provides the ability to retrieve a sub-set of the primary client registration information, which is stored with the Authorization Server.**

> Spring Boot 2.x auto-configuration binds each of the properties under `spring.security.oauth2.client.registration.[registrationId]` to an instance of ClientRegistration and then composes each of the `ClientRegistration` instance(s) within a `ClientRegistrationRepository`. [EXAMPLE CODE HERE](https://www.baeldung.com/spring-security-5-oauth2-login)  

Using Java Configuration Instead of application properties 
```java
@Controller
/**
 * Get the registration information of this application stored in Google ClientRegistrationRepository
 */
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

## (THE AUTHORIZATION) `OAuth2AuthorizedClientProvider`
A strategy for authorizing (or re-authorizing) an OAuth 2.0 Client (The Applciation that The user are currently using)  
- `ClientRegistration` is a representation of a client registered with an OAuth 2.0 or OpenID Connect 1.0 Provider.
- `OAuth2AuthorizedClient` is a representation of an Authorized Client.
   > For an Oauth2 Authorized provider must provide these two to authenticate

```
Provider
 '--- via Oauth2AccessToken 
      '-----> OAuth2AuthorizedClientService ---> OAuth2AuthorizedClientRepository
	    					   '--- OAuth2AuthorizedClient
```
- `Oauth2AuthrizedClientProvider` delegats the persistence of an `OAuth2AuthorizedClient`, typically using an `OAuth2AuthorizedClientService` or `OAuth2AuthorizedClientRepository` provides lookup associated with the `clientOAuth2AccessToken`  
	> [Example](https://www.programmersought.com/article/10451235590/)  

##### REVIEW of The Authentication
The Authentication Process In Spring Security
```
xxx_Manager is based on xxx_Provider via xxx_ProviderBuilder to build it

xxx_Provider is based on the xxx_Repositories
```

### Class OAuth2AuthorizedClient 

For **a client is considered to be authorized** when the end-user/Resource Owner has granted authorization to the client to access its protected resources.
```java
public class OAuth2AuthorizedClient implements Serializable {

	/**
	 * Constructs an {@code OAuth2AuthorizedClient} using the provided parameters.
	 * @param `clientRegistration`  the authorized client's registration
	 * @param `principalName`       the name of the End-User {@code Principal} (Resource Owner)
	 * @param `accessToken`         the access token credential granted
	 * @param `refreshToken`        the refresh token credential granted
	 */
	public OAuth2AuthorizedClient(ClientRegistration clientRegistration, 
				      String principalName,
			              OAuth2AccessToken accessToken, 
				      @Nullable OAuth2RefreshToken refreshToken) {
		
		Assert.notNull(clientRegistration, "clientRegistration cannot be null");
		Assert.hasText(principalName, "principalName cannot be empty");
		Assert.notNull(accessToken, "accessToken cannot be null");
		this.clientRegistration = clientRegistration;
		this.principalName = principalName;
		this.accessToken = accessToken;
		this.refreshToken = refreshToken;
	}
	
 // ....
```

### Class OAuth2AccessToken
```java
public class OAuth2AccessToken extends AbstractOAuth2Token {	 
	 /**
	 * Constructs an {@code OAuth2AccessToken} using the provided parameters.
	 * @param tokenType    the token type
	 * @param tokenValue   the token value
	 * @param issuedAt     the time at which the token was issued
	 * @param expiresAt    the expiration time on or after which the token MUST NOT be accepted
	 * @param scopes       the scope(s) associated to the token
	 */
	
	
	public OAuth2AccessToken(TokenType tokenType, String tokenValue, Instant issuedAt, Instant expiresAt) {
		this(tokenType, tokenValue, issuedAt, expiresAt, Collections.emptySet());
	}

	public OAuth2AccessToken(TokenType tokenType, String tokenValue, Instant issuedAt, Instant expiresAt,
			Set<String> scopes) {
		super(tokenValue, issuedAt, expiresAt);
		Assert.notNull(tokenType, "tokenType cannot be null");
		this.tokenType = tokenType;
		this.scopes = Collections.unmodifiableSet((scopes != null) ? scopes : Collections.emptySet());
	}
	
	//...
```
### Class AuthorizedCientManager 

The default implementation of `OAuth2AuthorizedClientManager` is `DefaultOAuth2AuthorizedClientManager`, which is associated with an `OAuth2AuthorizedClientProvider` that may support multiple authorization grant types using a delegation-based composite. 

- **The `OAuth2AuthorizedClientProviderBuilder` may be used to configure and build the delegation-based composite (e.g. password , emails ...).**
- `OAuth2AuthorizedClientManager` needs two repositories ( `ClientRegistrationRepository`, `OAuth2AuthorizedClientRepository`)

Build Up the Custom OAuth2 Authorized Client Manager 
```java
@Bean
public OAuth2AuthorizedClientManager authorizedClientManager(
	/*Which Third Party Application*/
	ClientRegistrationRepository clientRegistrationRepository,
	/*Get A Authorized Client*/
	OAuth2AuthorizedClientRepository authorizedClientRepository) 
	{

	/*******
	 * Building/Configuring A Custom Oauth2AuthroizedClientProvider 
	 * 		要求使用者需要遞交哪些資料作為認證
	 */
	OAuth2AuthorizedClientProvider authorizedClientProvider =
	    OAuth2AuthorizedClientProviderBuilder.builder()
		    .authorizationCode()
		    .refreshToken()
		    .clientCredentials()
		    .password()
		    .build();

	// Build Manager via DefaultOAuth2AuthorizedClientManager With CustomProvider
	DefaultOAuth2AuthorizedClientManager authorizedClientManager =
	    new DefaultOAuth2AuthorizedClientManager(clientRegistrationRepository, authorizedClientRepository);
	
	// The construction of Provider is based on clientRegistrationRepository and authorizedClinetRepository
	authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

	return authorizedClientManager;
}
```

## `contextAttributeMapper` 

If we need the `OAuth2AuthorizedClientProvider` requires the resource owner(end user)’s username and password to be available in `OAuth2AuthorizationContext.getAttributes().`

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

private Function <OAuth2AuthorizeRequest, Map<String, Object> > contextAttributesMapper() {
    return authorizeRequest -> {
        Map<String, Object> contextAttributes = Collections.emptyMap();
	
        HttpServletRequest servletRequest = authorizeRequest.getAttribute(HttpServletRequest.class.getName());
	
	// We get username and password from request
        String username = servletRequest.getParameter(OAuth2ParameterNames.USERNAME);
        String password = servletRequest.getParameter(OAuth2ParameterNames.PASSWORD);

        if (StringUtils.hasText(username) && StringUtils.hasText(password)) {
            contextAttributes = new HashMap<>();
	    
            /**
	     *  `PasswordOAuth2AuthorizedClientProvider` requires both attributes
             */
	    contextAttributes.put(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, username);
            contextAttributes.put(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, password);
        }
        return contextAttributes;
    };
}   
```

### AuthorizedClientServiceOAuth2AuthorizedClientManager

When operating data outside of a HttpServletRequest context(e.g clientRegistrationId, principal name ...etc), use `AuthorizedClientServiceOAuth2AuthorizedClientManager` instead. 
> [AuthorizedClientServiceOAuth2AuthorizedClientManager and DefaultOAuth2AuthorizedClientManager](https://stackoverflow.com/questions/67500742/what-is-the-difference-between-defaultoauth2authorizedclientmanager-and-authoriz)  

For Example
```java
@Bean
public OAuth2AuthorizedClientManager authorizedClientManager(
        ClientRegistrationRepository clientRegistrationRepository,
        OAuth2AuthorizedClientService authorizedClientService) {

    /**
     * Authenticate with attributes in client registration
     *	 not from HttpServletRequest (e.g. password , username , token ... etc)
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

# Oauth2User Filter  
There are two important filters
1. Oauth2AuthorizationRequestRedirectFilter (If the grant is valid then we goes the next filter `OAuth2LoginAuthenticationFilter`)
2. Oauth2LoginAuthenticationFilter

#### `OAuth2AuthorizationRequestRedirectFilter` handles for 
- When user clicks login via third party application in the client/application, `then OAuth2AuthorizationRequestRedirectFilter` will _resolve_ this request.
	> The request contains `client_id`、`scope` and `state` to form a `redirect_url` and redirect to third party authorized's url (github登入頁面)

#### `OAuth2LoginAuthenticationFilter` handles for

- (If the user grants the client can fetch resource from third party applocation ) This filter will add `Authorized Grant Code`, `state` ...etc ... parameters in the `redirect_url` 
	> `Oauth2LoginAuthenticationFilter` checks the grant code and state if they are valid then it returns access_token
- Parse the `redirect_url` `Authorized Grant Code` and `state` with the ones stored in the client's session.
	> if it is valid then it returns `access_token` url (so client can use this acces token to access third party resource)
- Client uses access token and Oauth2UserService to get third party protected resource and then return instance of Authenttication 
- `SecurityContextPersistenceFilter` will store protected resource in the local http session  (local endpoint) after that

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

**`DefaultOAuth2AuthorizationRequestResolver` determines to**
1. give a grant or not 
2. and then return instance of the `AuthorizaionRequest` to filter.

```java
//Returns the OAuth2AuthorizationRequest resolved from the provided HttpServletRequest or null if not available.
OAuth2AuthorizationRequest resolve(javax.servlet.http.HttpServletRequest request)	

//Returns the OAuth2AuthorizationRequest resolved from the provided HttpServletRequest or null if not available.
OAuth2AuthorizationRequest resolve(javax.servlet.http.HttpServletRequest request, java.lang.String registrationId)	

//Sets the Consumer to be provided the OAuth2AuthorizationRequest.Builder allowing for further customizations.
void setAuthorizationRequestCustomizer(java.util.function.Consumer<OAuth2AuthorizationRequest.Builder> authorizationRequestCustomizer)	

/**
 *  resolve request to AuthorizaionRequest
 */
private OAuth2AuthorizationRequest resolve(HttpServletRequest request, String registrationId, String redirectUriAction) {
	if (registrationId == null) {
		return null;
	}
	
	// Find if the Client is registered or not  
	ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
	if (clientRegistration == null) {
		throw new IllegalArgumentException("Invalid Client Registration with Id: " + registrationId);
	}
	
	// Create Oauth2AuthorizationRequest's extra attributes via clientRegistration and attributes in httpservletrequest
	Map<String, Object> attributes = new HashMap<>();
	
	attributes.put(OAuth2ParameterNames.REGISTRATION_ID, clientRegistration.getRegistrationId());
	OAuth2AuthorizationRequest.Builder builder = getBuilder(clientRegistration, attributes);

	//** Expand ReirectUri for redirect endpoint
	//*  ( the one in client registration + each attributes in requqest )
	String redirectUriStr = expandRedirectUri(request, clientRegistration, redirectUriAction);


	// Build up a OAuth2AuthorizationRequest 
	// clientId, authorized endpoint, redirect endpoint , scope, state, extra attributes 
	builder.clientId(clientRegistration.getClientId()) // this authorizedRequest belongs who 
			.authorizationUri(clientRegistration.getProviderDetails().getAuthorizationUri()) // authorized endpoint
			.redirectUri(redirectUriStr) 	  // redirect endpoint (with scope, state) to the user 
			.scopes(clientRegistration.getScopes())
			.state(this.stateGenerator.generateKey())
			.attributes(attributes); //  attributes ( registration id, ... etc ...)
	
	this.authorizationRequestCustomizer.accept(builder);
	return builder.build();
}
```
#### Generate Expand Redire URI (URI from ClientREgistration + URI from HttpServletRequest's Attributes)

![image](https://user-images.githubusercontent.com/68631186/122837983-a7f57a00-d327-11eb-91c6-beef66472fd6.png)
```java 
/**
 * Expands the {@link ClientRegistration#getRedirectUri()} with following provided variables:
 * - baseUrl (e.g. https://localhost/app) 
 * - baseScheme (e.g. https) 
 * - baseHost (e.g. localhost) 
 * - basePort (e.g. :8080) 
 * - basePath (e.g. /app) 
 * - registrationId (e.g. google, facebook, github) 
 * - action (e.g. login) 
 * - Null variables are provided as empty strings.
 ---------------------------------------------
 * Default redirectUri is: {@code org.springframework.security.config.oauth2.client.CommonOAuth2Provider#DEFAULT_REDIRECT_URL}
 */
private static String expandRedirectUri(HttpServletRequest request, ClientRegistration clientRegistration,
		String action) {
	/* chiletRegistration : get our default reditrect uri */
	/* request : get the attributes we need to exapnd to default redirecturi*/

        // Map<String,Strig> attributes from httpServletrequest and clientRegistration
	Map<String, String> uriVariables = new HashMap<>();
	uriVariables.put("registrationId", clientRegistration.getRegistrationId());
	

	// using class `UriComponents` helps us get Attibutes in the httpservletrequest
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
	
	// Form a new (RedirectUri) + (Urivariable) uri
	// RedirectUri : {baseScheme}://{baseHost}{basePort}{basePath}.
	return UriComponentsBuilder
			.fromUriString(clientRegistration.getRedirectUri())
				.buildAndExpand(uriVariables)
			.toUriString();
}

public final class UrlUtil{
	// .. other methods ...
	
	/**
	 *  Get Attribute from HttpservletRequest 
	 */
	public static String buildRequestUrl(HttpServletRequest r) {
	return buildRequestUrl(r.getServletPath(), r.getRequestURI(), r.getContextPath(), r.getPathInfo(),
			r.getQueryString());
	}
}

/* get URI or URL */
public interface HttpServletRequest extends ServletRequest {
  /**
     * Returns the part of this request's URL from the protocol
     * name up to the query string in the first line of the HTTP request.
     * The web container does not decode this String.
     * For example:
     *
     * <table summary="Examples of Returned Values">
     * <tr align=left><th>First line of HTTP request </th>
     * <tr><td>POST /some/path.html HTTP/1.1<td>	<td>/some/path.html
     * <tr><td>GET http://foo.bar/a.html HTTP/1.0       <td><td>/a.html
     * <tr><td>HEAD /xyz?a=b HTTP/1.1			<td><td>/xyz
     *
     * To reconstruct an URL with a scheme and host, use {@link HttpUtils#getRequestURL}.
     *
     * @return		a <code>String</code> containing
     *			the part of the URL from the
     *			protocol name up to the query string
     */
    public String getRequestURI();

    /**
     * The returned URL contains a `protocol`, `server name`, `port`
     * `number`, and `server path`, but it does not include **query
     * string parameters**.
     *
     * Because this method returns a <code>StringBuffer</code>,
     * not a string, you can modify the URL easily, for example,
     * to append query parameters.
     *
     * <p>This method is useful for creating redirect messages
     * and for reporting errors.
     *
     * @return		a <code>StringBuffer</code> object containing
     *			the reconstructed URL
     */
    public StringBuffer getRequestURL();

     //...
}

public class HttpUtils {
   /**
     *
     * Reconstructs the URL the client used to make the request,
     * using information in the <code>HttpServletRequest</code> object.
     * The returned URL contains a protocol, server name, port
     * number, and server path, but it does not include query
     * string parameters.
     * 
     * <p>Because this method returns a <code>StringBuffer</code>,
     * not a string, you can modify the URL easily, for example,
     * to append query parameters.
     *
     * <p>This method is useful for creating redirect messages
     * and for reporting errors.
     *
     * @param req	a <code>HttpServletRequest</code> object
     *			containing the client's request
     * 
     * @return		a <code>StringBuffer</code> object containing
     *			the reconstructed URL
     */
    public static StringBuffer getRequestURL (HttpServletRequest req) {
        StringBuffer url = new StringBuffer();
        String scheme = req.getScheme ();
        int port = req.getServerPort ();
        String urlPath = req.getRequestURI();

        //String		servletPath = req.getServletPath ();
        //String		pathInfo = req.getPathInfo ();

        url.append (scheme);		// http, https
        url.append ("://");
        url.append (req.getServerName ());
        if ((scheme.equals ("http") && port != 80)
        || (scheme.equals ("https") && port != 443)) {
            url.append (':');
            url.append (req.getServerPort ());
        }
        //if (servletPath != null)
        //    url.append (servletPath);
        //if (pathInfo != null)
        //    url.append (pathInfo);
        url.append(urlPath);

        return url;
    }
}
```

### Redirct to Authorized page
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
    // authorizationRequest.getAuthorizationRequestUri() : third party appliction login page (Wart daruaf, Der Nutzer gibt password/emaill ein)
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
    // To the page that user from third party application to grant or deny the access
    response.sendRedirect(redirectUrl);
}
```

## OAuth2LoginAuthenticationFilter
[ref](https://www.cnblogs.com/felordcn/p/13992477.html)  
![image](https://user-images.githubusercontent.com/68631186/122872974-cd07de00-d363-11eb-88a4-67edc7b91d04.png)  
This filter
1. Process an Oauth 2.0 Authorization Response (**by intercepting authorization grant code returned by Authorization Server**) 
2. Generate A Authentication `OAuth2LoginAuthenticationToken` and delegates it to the  `AuthenticationManager` to do a authentication
3. Creat A valid OAuth2LoginAuthenticationToken and Oauth2AuthorizedClient then return `OAuth2AuthenticationToken` save them in the SecurityContextRepository and OAuth2AuthorizedClientRepository
```java
/**
 * An implementation of an {@link AbstractAuthenticationProcessingFilter} for OAuth 2.0 Login.
 * This authentication {@code Filter} handles the processing of an OAuth 2.0 Authorization Response 
 *      for the authorization code grant flow 
 *	and delegates an
 * 		{@link OAuth2LoginAuthenticationToken} to the {@link AuthenticationManager} 
 * 		to log in the End-User.
 *
 /**********************Checking The Grant Code and State from Clinet***************************
 *The OAuth 2.0 Authorization Response is processed as follows:
 *      Assuming the End-User (Resource Owner) has granted access to the Client, 
 *    	the Authorization Server will append the 
 *		1. OAuth2ParameterNames#CODE `code` and OAuth2ParameterNames#STATE `state` parameters to 
 *		2. the OAuth2ParameterNames#REDIRECT_URI `redirect_uri` (provided in the Oauth2AuthorizedRequest)
 *	and redirect the End-User's user-agent back to this {@code Filter}
 *
 /***********************Generate the Token to client**************************************
 * This {@code Filter} will then create an `OAuth2LoginAuthenticationToken` with
 * 	the OAuth2ParameterNames#CODE `code` received 
 * 	and delegate it to the `AuthenticationManager` to authenticate.
 *
 /***********************A Valid User in third party application**********************************
 * Upon a successful authentication, an OAuth2AuthenticationToken is created
 * 	(representing the End-User {@code Principal}) and associated to the
 * 	{@link OAuth2AuthorizedClient Authorized Client} using the
 * 	{@link OAuth2AuthorizedClientRepository}.
 *
 /***********************Save the this valid user principal into the local protected resource********
 * Finally, the {@link OAuth2AuthenticationToken} is returned and ultimately stored in
 * 	the {@link SecurityContextRepository} to complete the authentication processing.
 */
public class OAuth2LoginAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	// Default_url, and Static final String attributes ....
	
	private ClientRegistrationRepository clientRegistrationRepository;
	private OAuth2AuthorizedClientRepository authorizedClientRepository;
	private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository = new HttpSessionOAuth2AuthorizationRequestRepository();

        // other methods ....
	
	// Execute the Authentication for what the ueser gave in the client (password, email, state , scope ... etc  )
        @Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
			
		MultiValueMap<String, String> params = OAuth2AuthorizationResponseUtils.toMultiMap(request.getParameterMap());
		// check state and grant code 
		if (!OAuth2AuthorizationResponseUtils.isAuthorizationResponse(params)) {
			OAuth2Error oauth2Error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}
		
		/**
		 * Intercept the Oauth2AuthorizationRequest from Authorization Server 
		 * associated in the httpsession
		 */
		OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestRepository
				.removeAuthorizationRequest(request, response);
		if (authorizationRequest == null) {
			OAuth2Error oauth2Error = new OAuth2Error(AUTHORIZATION_REQUEST_NOT_FOUND_ERROR_CODE);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}
		
		/**
		 * Find the legit client from Authentication Server via authroizartionRequest and clientRegistrationRepository
		 *	if there is no such client then throw Oauth2AuthenticationExption
		 */
		String registrationId = authorizationRequest.getAttribute(OAuth2ParameterNames.REGISTRATION_ID);
		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
		if (clientRegistration == null) {
			OAuth2Error oauth2Error = new OAuth2Error(CLIENT_REGISTRATION_NOT_FOUND_ERROR_CODE,
					"Client Registration not found with Id: " + registrationId, null);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}
		
		/**
		 *  get Attributes from httpservlet request
		 *  By converting httpservelet request to Url then via UriComponentsBuilder to get each attribute
		 */
		String redirectUri = UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
				.replaceQuery(null)
				.build()
				.toUriString();
				
				
		OAuth2AuthorizationResponse authorizationResponse = OAuth2AuthorizationResponseUtils.convert(params,redirectUri);
		Object authenticationDetails = this.authenticationDetailsSource.buildDetails(request);
		
		// 建立含有token的Authentication Request
		OAuth2LoginAuthenticationToken authenticationRequest = new OAuth2LoginAuthenticationToken(clientRegistration,
				new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse));
		authenticationRequest.setDetails(authenticationDetails);
		setDetails
		// 驗證透過AuthenticationManager
		OAuth2LoginAuthenticationToken authenticationResult = (OAuth2LoginAuthenticationToken) this
				.getAuthenticationManager().authenticate(authenticationRequest);
		
		// 建立代表該User的Token
		OAuth2AuthenticationToken oauth2Authentication = new OAuth2AuthenticationToken(
				authenticationResult.getPrincipal(), authenticationResult.getAuthorities(),
				authenticationResult.getClientRegistration().getRegistrationId());
		oauth2Authentication.setDetails(authenticationDetails);
		// 把Toke存入Authorization Server對應的Client中
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
				authenticationResult.getClientRegistration(), oauth2Authentication.getName(),
				authenticationResult.getAccessToken(), authenticationResult.getRefreshToken());
		this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, oauth2Authentication, request, response);
		
		return oauth2Authentication;
	}
}
```
[Reference](https://zhuanlan.zhihu.com/p/100625981)

## Intercept The Oauth2AuthorizationRequest
```java
// Intercept the OAuth2AuthorizationRequest
@Override
public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request) {
	Assert.notNull(request, "request cannot be null");
	
	// getState from the request
	String stateParameter = this.getStateParameter(request);
	if (stateParameter == null) {
		return null;
	}
	
	// Map<"state", state_code> 
	Map<String, OAuth2AuthorizationRequest> authorizationRequests = this.getAuthorizationRequests(request);
	
	// compare with `state`
	OAuth2AuthorizationRequest originalRequest = authorizationRequests.remove(stateParameter);
	
	if (authorizationRequests.size() == 0) {
	// remove state in this the session
		request.getSession().removeAttribute(this.sessionAttributeName);
	}
	else if (authorizationRequests.size() == 1) {
	// add state
		request.getSession().setAttribute(this.sessionAttributeName,
				authorizationRequests.values().iterator().next());
	}
	else {
	// add state
		request.getSession().setAttribute(this.sessionAttributeName, authorizationRequests);
	}
	return originalRequest;
}

/**
 * Get Map<"state" , OAuth2AuthorizationRequest state_code> instance from the `OAuth2AuthorizationRequest` or `Map` 
 * 	From session via HttpServletRequest and return this Map instance
 */
private Map<String, OAuth2AuthorizationRequest> getAuthorizationRequests(HttpServletRequest request) {

		// returns a session only if there is one associated with the request (if not then dont create new session automatically)
		HttpSession session = request.getSession(false);
		
		// get session attribute's value coulde be an instance of OAuth2AuthorizationRequest or Map 
		Object sessionAttributeValue = (session != null) ? session.getAttribute(this.sessionAttributeName) : null;
		if (sessionAttributeValue == null) {
			return new HashMap<>();
		}
		
		else if (sessionAttributeValue instanceof OAuth2AuthorizationRequest) {
		// get Oauth2AuthorizationRerquest's attribute `state`
			OAuth2AuthorizationRequest auth2AuthorizationRequest = (OAuth2AuthorizationRequest) sessionAttributeValue;
			
			Map<String, OAuth2AuthorizationRequest> authorizationRequests = new HashMap<>(1);
			// For comparing with `state`
			authorizationRequests.put(auth2AuthorizationRequest.getState(), auth2AuthorizationRequest);
			return authorizationRequests;
		}
		else if (sessionAttributeValue instanceof Map) {
			@SuppressWarnings("unchecked")
			Map<String, OAuth2AuthorizationRequest> authorizationRequests = (Map<String, OAuth2AuthorizationRequest>) sessionAttributeValue;
			return authorizationRequests;
		}
		else {
			throw new IllegalStateException(
					"authorizationRequests is supposed to be a Map or OAuth2AuthorizationRequest but actually is a "
							+ sessionAttributeValue.getClass());
		}
	}


/**
 * Check the `state` parameter
 */
final class OAuth2AuthorizationResponseUtils {

	// other methods ...
	
	// get attribute (grant code, state, Error ... ) from @Parameter request
	static OAuth2AuthorizationResponse convert(MultiValueMap<String, String> request, String redirectUri) {
			String code = request.getFirst(OAuth2ParameterNames.CODE);
			String errorCode = request.getFirst(OAuth2ParameterNames.ERROR);
			String state = request.getFirst(OAuth2ParameterNames.STATE);
			
			if (StringUtils.hasText(code)) {
				// Success 
				return OAuth2AuthorizationResponse.success(code).redirectUri(redirectUri).state(state).build();
			}
			
			String errorDescription = request.getFirst(OAuth2ParameterNames.ERROR_DESCRIPTION);
			String errorUri = request.getFirst(OAuth2ParameterNames.ERROR_URI);
			
			// Error 
			return OAuth2AuthorizationResponse.error(errorCode)
					.redirectUri(redirectUri)
					.errorDescription(errorDescription)
					.errorUri(errorUri)
					.state(state)
					.build();
		}
}

```

### Authenticating Access Token

```java
public class OAuth2LoginAuthenticationProvider implements AuthenticationProvider {
    
    //...
    
    @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    OAuth2LoginAuthenticationToken authorizationCodeAuthentication = (OAuth2LoginAuthenticationToken) authentication;

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
  
  //....
}

```


#### Conclusion of the filters

1. OAuth2AuthorizationRequestResolver resolves the request from client，
   > If the request is not null, it returns an instance of OAuth2AuthorizationRequest including `client_id`, `state`, `redirect_uri`

2. Store this oAuth2AuthorizationRequest via `authorizationRequestRepository.saveAuthorizationRequest` to the http session 
   > Authorization Server can look up authorization request's attribute `state` in the httpsession to compare wiht `state` from client's request to prevent the csrf attack

3. (if retured OAuth2AuthorizationRequest instance is not null)，filter will call `response.sendRedirect` methods (to the authorized endpoint e.g github login page ... etc)
   > Oauth2AuthorizationRequest sends to the frontend's response to redirect browser to the authorized page for the user entering password/email ..etc to be authenticated by Loginfilter

## AuthorizationRequestRepository (Authorization Endpoint)

The `AuthorizationRequestRepository` is responsible for the persistence of the `OAuth2AuthorizationRequest` from the time the Authorization Request is initiated to the time the Authorization Response is received (intercepted by `OAuth2LoginAuthenticationFilter`).

It is Used by the `OAuth2AuthorizationRequestRedirectFilter` for persisting the `OAuth2AuthorizationRequest` before it initiates the authorization code grant flow.  
As well, used by the `OAuth2LoginAuthenticationFilter` for resolving the associated Authorization Request when handling the callback of the Authorization Response.  

REVIEW of `OAuth2AuhroizationRequest`  
- A representation of an OAuth 2.0 Authorization Request for the authorization code grant type or implicit grant type.
- [code](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/oauth2/core/endpoint/OAuth2AuthorizationRequest.html)

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
                            //...
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

}
```

## Oauth2 Authentication Introspecter

It decodes String tokens into validated instances of `OAuth2AuthenticatedPrincipal`

The deafult `QpaueTokenIntrospector` exposes itself as a bean to be injected
```java
@Bean
public OpaqueTokenIntrospector introspector() {
    return new NimbusOpaqueTokenIntrospector(introspectionUri, clientId, clientSecret);
}
```

Or creating a custom introspector for example Extracting Authorities Manually ...
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
then expose it as bean
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

REVEIW
- Authorization Endpoint: **Used by the client** to obtain authorization from the resource owner via user-agent redirection. 
- Token Endpoint: **Used by the client** to exchange an authorization grant for an access token, typically with client authentication. 
- Redirection Endpoint: **Used by the authorization** server to return responses containing authorization credentials to the client via the resource owner user-agent. 
- The UserInfo Endpoint : is an OAuth 2.0 Protected Resource that returns claims about the authenticated end-user (**Instance of Authentication**). 
  > The client makes a request to the UserInfo Endpoint by using an access token obtained through OpenID Connect Authentication (Authorization Server). 
  > These claims are normally represented by a JSON object that contains a collection of name-value pairs for the claims.


### A Custom Oauth2 Login Flow
 
1.The OAuth2 login flow will be initiated by the frontend client by sending the user to the endpoint 
 	> `http://localhost:8080/oauth2/authorize/{provider}?redirect_uri=<redirect_uri_after_login>`.
	> The `{provider}` path parameter is one of google,github or other third party application. 
	> The `redirect_uri` is the URI to which the user will be redirected once the authentication with the OAuth2 provider is successful(login from third party application).

2. On receiving the Oauth2authorized Request object, Spring Security’s client will redirect the user to the (Authorized Endpoint) AuthorizationUrl of the supplied provider(**the login page**).

3. All the state (attribute from httpservletRequest) associated/related to the authorization request is saved using the `authorizationRequestRepository` specified in the SecurityConfig.

4. The user(you) now allows/denies permission to your app on the provider’s page. 
	> If the user allows permission to the app(allowing to use third party account to login the app),   
	> the provider will redirect the user to the callback url `http://localhost:8080/oauth2/callback/{provider}` with an authorization code.
	> If the user denies the permission, he/her will be redirected to the same callbackUrl but with an `error` (more details on filter chapter).

5. If the OAuth2 callback results in an error, Spring security will invoke the `oAuth2AuthenticationFailureHandler` specified in the above SecurityConfig.
5. If the OAuth2 callback is successful and it contains the authorization code, Spring Security will exchange the authorization_code for an access_token and invoke the `customOAuth2UserService` specified in the the (httpScurity) SecurityConfig.

6. The customOAuth2UserService retrieves the details of the authenticated user and creates a new entry in the database or updates the existing entry with the same email.

7. Upon a successful authentication, the `oAuth2AuthenticationSuccessHandler` is invoked. 
	>It creates a JWT authentication token for the user and sends the user to the `redirect_uri` along with the JWT token in a query string.


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



## redirection Endpoint

The Redirection Endpoint is used by the Authorization Server for returning the Authorization Response (which contains the authorization credentials and will be intercepted by the LoginAuthenticationfilter) to the client

The default Authorization Response baseUri
```json
/login/oauth2/code/*
```

We can customize it to any other URL of our choice `(/oauth2/callback/)`.  

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

## userInfoEndpoint (An AuthenticationManager)

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
