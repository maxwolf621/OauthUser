# Filter For Oauth2User  

There are two important filters
1. `Oauth2AuthorizationRequestRedirectFilter` (If the grant is valid then we goes the next filter `OAuth2LoginAuthenticationFilter`)
2. `Oauth2LoginAuthenticationFilter`

#### `OAuth2AuthorizationRequestRedirectFilter` handles for 

When user clicks login via third party application in the client/application, then `OAuth2AuthorizationRequestRedirectFilter` will _resolve_ this request

- The request contains `client_id`、`scope` and `state` to form a `redirect_url` and redirect to third party authorized's url for asking the grant from resource  owner (redirect第三方登入頁面允許resource onwer授權)

[Oauth2 Filter Code](https://www.gushiciku.cn/pl/pnSK/zh-/tw)   

1. The `OAuth2AuthorizationRequestRedirectFilter` uses an `OAuth2AuthorizationRequestResolver` to **RESOLVE**/build up `HttpServletRequest` an `OAuth2AuthorizationRequest` 
2. **Initiate the Authorization Code grant flow by redirecting the end-user’s user-agent to the Authorization Server’s Authorization Endpoint**.

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
- If the grant is valid then we goes the next filter `OAuth2LoginAuthenticationFilter`  

### Resolver

```java
{@cpde DefaultOAuth2AuthorizationRequestResolver}
'--extract {@code registrationId} from "/oauth2/authorization/{registrationId}"
   '--use {@code registrationId} build {@code Oauth2AuthorizationRequest}
```
- The default implementation `DefaultOAuth2AuthorizationRequestResolver` matches on the (default) path `/oauth2/authorization/{registrationId}` extracting the `registrationId` (from class `ClientRegistration`) and using it to build the `OAuth2AuthorizationRequest` for the associated `ClientRegistration`.  
  > **`DefaultOAuth2AuthorizationRequestResolver` determines to** give a grant or not and then return instance of the `AuthorizaionRequest` to filter.

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
	
	// Find if the Client(OUR SPRING APPLICATION) is registered on third party application or not  
	ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
	if (clientRegistration == null) {
	
		throw new IllegalArgumentException("Invalid Client Registration with Id: " + registrationId);
	}
	
	// Create Oauth2AuthorizationRequest's extra attributes 
	// via clientRegistration and attributes in httpservletrequest
	Map<String, Object> attributes = new HashMap<>();
	
	attributes.put(OAuth2ParameterNames.REGISTRATION_ID, clientRegistration.getRegistrationId());
	OAuth2AuthorizationRequest.Builder builder = getBuilder(clientRegistration, attributes);

	//Expand ReirectUri for redirect endpoint
	//( the one in client registration + each attributes in requqest )
	String redirectUriStr = expandRedirectUri(request, clientRegistration, redirectUriAction);


	// Build up a OAuth2AuthorizationRequest 
	// clientId, authorized endpoint, redirect endpoint , scope, state, extra attributes 
	builder.clientId(clientRegistration.getClientId()) // this authorizedRequest belongs who 
			.authorizationUri(clientRegistration.getProviderDetails().getAuthorizationUri()) // authorized endpoint
			.redirectUri(redirectUriStr) 	  // redirect endpoint (with scope, state) to the user 
			.scopes(clientRegistration.getScopes())
			.state(this.stateGenerator.generateKey())
			.attributes(attributes);          //  attributes ( registration id, ... etc ...)
	
	this.authorizationRequestCustomizer.accept(builder);
	return builder.build();
}
```

#### `expandRedirectUri`

```diff
expandRedirectUri = URI_ClientRegistration + HttpServletRequest's Attributes
````
- Generate Expand Redirect URI (e.g. URI from `ClientRegistration` + `HttpServletRequest`'s Attributes)

![image](https://user-images.githubusercontent.com/68631186/122837983-a7f57a00-d327-11eb-91c6-beef66472fd6.png)  

```java 
/**
 * Expands the {@link ClientRegistration#getRedirectUri()} with following provided variables:
 * <li> baseUrl (e.g. https://localhost/app)            </li>
 * <li> baseScheme (e.g. https)                         </li>      
 * <li> baseHost (e.g. localhost)                       </li>
 * <li> basePort (e.g. :8080)                           </li>       
 * <li> basePath (e.g. /app)                            </li> 
 * <li> registrationId (e.g. google, facebook, github)  </li> 
 * <li> action (e.g. login)                             </li>
 * <li> Null variables are provided as empty string
 * Default redirectUri is: 
 * {@code org.springframework.security.config.oauth2.client.CommonOAuth2Provider#DEFAULT_REDIRECT_URL}
 */
private static String expandRedirectUri(HttpServletRequest request, 
                                        ClientRegistration clientRegistration,
					String action) {
	
	/**
	  * <li> clientRegistration : Get default reditrect uri </li>
	  * <li> request : 
	  *      Get the attributes we need for exapnding 
	  *      default redirecturi that fetched from clientRegistration </li>
	  */

        // Map<String,Strig> attributes from httpServletrequest and clientRegistration
	Map<String, String> uriVariables = new HashMap<>();
	uriVariables.put("registrationId", clientRegistration.getRegistrationId());
	
	/**
	  * {@code UrlUtils} build httUrl based on {@code HttpServletRequest}
	  */
	UriComponents uriComponents = UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
			.replacePath(request.getContextPath())
			.replaceQuery(null)
			.fragment(null)
			.build();
	
	/**
	 *  using {@code UriComponents} helps us get Attibutes in the {@code HttpServletRequest} 
	 */
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
	
	/**
	  * <p> Form a new <pre> (RedirectUri) + (Urivariable) </pre> Uri 
	  *     RedirectUri : <pre> {baseScheme}://{baseHost}{basePort}{basePath}. </pre></p>
	  * <p> Get {@code RedirectUri} from {@code clientRegistration} 
	  *     And Expand it with attributes that extract from {@code HttpServletRequest} 
	  *     and {@code clientRegistration} </p>
	  */
	return UriComponentsBuilder
			.fromUriString(clientRegistration.getRedirectUri())
		        .buildAndExpand(uriVariables)
			.toUriString();
}
```

Usage of `UrlUtil`
```java
public final class UrlUtil{
	// ...
	
	/**
	 *  Get Attributes from {@code HttpservletRequest} 
	 */
	public static String buildRequestUrl(HttpServletRequest r) {
	return buildRequestUrl(r.getServletPath(), r.getRequestURI(), 
		               r.getContextPath(), r.getPathInfo(),
			       r.getQueryString());
	}
}

/**
  * To Get URI or URL 
  */
public interface HttpServletRequest extends ServletRequest {
    /**
     * <p> Returns the part of this request's URL from the protocol
     * name up to the query string in the first line of the HTTP request. </p>
     * <p> The web container does not decode this String. </p>
     *
     * <p> For example: </p>
     * <table summary="Examples of Returned Values">
     * <tr align=left><th> First line of HTTP request </th>
     * <tr><td>	           POST /some/path.html HTTP/1.1<td>	<td>	/some/path.html
     * <tr><td>	           GET http://foo.bar/a.html HTTP/1.0   <td><td>/a.html
     * <tr><td>	           HEAD /xyz?a=b HTTP/1.1		<td><td>/xyz
     *
     * <p> To reconstruct an URL with a scheme and host, 
     *     use {@link HttpUtils#getRequestURL}. </p>
     *
     * @return a <code>String</code> containing
     *	       the part of the URL from the
     *	       protocol name up to the query string
     */
    public String getRequestURI();

    /**
     * <p> The returned URL contains a `protocol`, `server name`, `port`
     * `number`, and `server path`, but it does not include query
     * string parameters.</p>
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
     * <p> Reconstructs the URL the client used to make the request,
     * using information in the <code>HttpServletRequest</code> object. </p>
     * <p> The returned URL contains a protocol, server name, port
     * number, and server path, but it does not include query
     * string parameters. </p>
     * 
     * <p>Because this method returns a <code>StringBuffer</code>,
     * not a string, you can modify the URL easily, for example,
     * to append query parameters. </p>
     *
     * <p>This method is useful for creating redirect messages
     * and for reporting errors. </p>
     *
     * @param req	a {@code HttpServletRequest} object
     *			containing the client's request
     * 
     * @return		a {@code StringBuffer} object containing
     *			the reconstructed URL
     */
    public static StringBuffer getRequestURL (HttpServletRequest req) {
    
        StringBuffer url = new StringBuffer();
	
        String scheme = req.getScheme ();
        int port = req.getServerPort ();
	
        String urlPath = req.getRequestURI();

        //String servletPath = req.getServletPath ();
        //String pathInfo = req.getPathInfo ();

        url.append (scheme);  // http, https
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
[FORWARD and REDIRECT](https://stackoverflow.com/questions/20371220/what-is-the-difference-between-response-sendredirect-and-request-getrequestdis)  

```java
private void sendRedirectForAuthorization(HttpServletRequest request, HttpServletResponse response,
                                          OAuth2AuthorizationRequest authorizationRequest) throws IOException {
    // check the Auhtorization Grant Type
    if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationRequest.getGrantType())) {
    	
	// save the request payloads (state, url ,... etc ) in http session
        this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, request, response);
    }
    
    /**
     * <p> {@code authorizationRedirectStrategy} is {@code DefaultRedirectStrategy} </p>
     * <p> {@code authorizationRequest.getAuthorizationRequestUri()}
     *     third party appliction login page (Wart daruaf, Der Nutzer gibt password/emaill ein) </p>
     */
    this.authorizationRedirectStrategy.sendRedirect(request, response, authorizationRequest.getAuthorizationRequestUri());
}
```

Usage of `sendRedirect`
```java
public void sendRedirect(HttpServletRequest request, 
			 HttpServletResponse response,
                         String url) throws IOException {
    String redirectUrl = calculateRedirectUrl(request.getContextPath(), url);
    redirectUrl = response.encodeRedirectURL(redirectUrl);
    
    if (logger.isDebugEnabled()) {
        logger.debug("Redirecting to '" + redirectUrl + "'");
    }
 
    
    // To the page that user from third party application to grant or deny the access
    response.sendRedirect(redirectUrl);
}
```

## [`OAuth2LoginAuthenticationFilter`](https://zhuanlan.zhihu.com/p/100625981) handles for

[reference](https://www.cnblogs.com/felordcn/p/13992477.html)  


1. If the user grants the client can fetch his resource from third party applocation,then this filter will add Authorized Grant Code, state ...etc in the `redirect_url`  

2. Parse the `redirect_url`, `Authorized Grant Code` and `state` with the ones stored in the client's session (client here is our spring application)
  > If they are valid then the filter returns `access_token` url 

3. Client uses access token and calls (its spring api) `Oauth2UserService` to get third party protected resource for returning instance of `Authenttication` 

4. `SecurityContextPersistenceFilter` will store protected resource in the local http session  (local endpoint) after that


![image](https://user-images.githubusercontent.com/68631186/122872974-cd07de00-d363-11eb-88a4-67edc7b91d04.png)   

```java
/**
 * <p> Process an Oauth 2.0 Authorization Response 
 * (by intercepting authorization grant code returned by Authorization Server**) </p> 
 * <p> Generate A Authentication `OAuth2LoginAuthenticationToken` 
 *     and delegates it to the  `AuthenticationManager` to do a authentication </p>
 * <p> Creat A valid OAuth2LoginAuthenticationToken and Oauth2AuthorizedClient
 *      then return `OAuth2AuthenticationToken` save them 
 *      in the SecurityContextRepository and OAuth2AuthorizedClientRepository </p>
 * 
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


## Intercept The `OAuth2AuthorizationRequest`

```java
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
 * From session via HttpServletRequest and return this Map instance
 */
private Map<String, OAuth2AuthorizationRequest> getAuthorizationRequests(HttpServletRequest request) {

		// Return a session only if there is one associated with the request (if not then dont create new session automatically)
		HttpSession session = request.getSession(false);
		
		// Get session attribute's value coulde be an instance of OAuth2AuthorizationRequest or Map 
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
 * Check the {@code state} parameter
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

1. `OAuth2AuthorizationRequestResolver` resolves the (`HttpServletRequest`) request from client，
   > If the request is not `null`, it returns an instance of `OAuth2AuthorizationRequest` including `client_id`, `state`, `redirect_uri` ...

2. Store the valid `OAuth2AuthorizationRequest` via `authorizationRequestRepository.saveAuthorizationRequest` to the client's(spring application) session 
   > Authorization Server can look up authorization request's attribute `state` in the httpsession to compare wiht `state` from client's request to prevent the csrf attack

3. (If retured `OAuth2AuthorizationRequest` instance is not `null`)，filter will call `response.sendRedirect` method (to the Authorized Endpoint)
   > `OAuth2AuthorizationRequest` sent the frontend's response to redirect browser to the authorized page for the user entering password/email ..etc to be authenticated by Loginfilter
