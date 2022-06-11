# Filter For Oauth2User  

[Oauth2 Filter Code](https://www.gushiciku.cn/pl/pnSK/zh-/tw)  

There are two important filters for OAuth2 Flow    
`Oauth2AuthorizationRequestRedirectFilter` (If the authorization grant is valid it goes `Oauth2LoginAuthenticationFilter`)

## `OAuth2AuthorizationRequestRedirectFilter` 

When Client asks for Authorization grant via `httpSerletReq` , then `OAuth2AuthorizationRequestRedirectFilter` will _resolve/parse_ the request
- The request contains `client_id`、`scope` and `state` to form a callback `redirect_url` and redirect to third party authorized's url for asking the grant from resource owner 
 
The `OAuth2AuthorizationRequestRedirectFilter` uses an `OAuth2AuthorizationRequestResolver` to **RESOLVE** `HttpServletRequest` an `OAuth2AuthorizationRequest`    

**Initiate the Authorization Code grant flow by redirecting the end-user’s user-agent to the Authorization Server’s Authorization Endpoint.**.

```java
public class OAuth2AuthorizationRequestRedirectFilter extends OncePerRequestFilter {
  
  //...

  @Override
  protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
    try {
		//  Resolve an Oauth2AuthorizationRequest from httpServletRequest
		OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestResolver.resolve(request);
		
		if (authorizationRequest != null) {
			// Initiate Redirect URL
			this.sendRedirectForAuthorization(request, response, authorizationRequest);
			
			return;
      	}
	} catch (Exception failed) {
		this.unsuccessfulRedirectForAuthorization(request, response, failed);
		return;
    }
    
    //...
  }
}   
```

```java
DefaultOAuth2AuthorizationRequestResolver
+--extract {@code registrationId} from "/oauth2/authorization/{registrationId}"
   '--use registrationId
      build Oauth2AuthorizationRequest 
      for the associated ClientRegistration
```
- The default implementation `DefaultOAuth2AuthorizationRequestResolver` matches on the (default) path `/oauth2/authorization/{registrationId}` extracting the `registrationId` (from `ClientRegistration`) and new the `OAuth2AuthorizationRequest` for the associated `ClientRegistration`.  

**`DefaultOAuth2AuthorizationRequestResolver` determines to** give a grant or not and then return instance of the `AuthorizationRequest` to `OAuth2AuthorizationRequestRedirectFilter` 

```java
/**
  * @return the OAuth2AuthorizationRequest resolved 
  *         from the provided HttpServletRequest 
  *         or null if not available.
  */
OAuth2AuthorizationRequest resolve(
	javax.servlet.http.HttpServletRequest request)	
OAuth2AuthorizationRequest resolve(
	javax.servlet.http.HttpServletRequest request, java.lang.String registrationId)	

private OAuth2AuthorizationRequest resolve(HttpServletRequest request, 
										   String registrationId, 
										   String redirectUriAction) 
{
	if (registrationId == null) {
		return null;
	}
	
	ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);

	if (clientRegistration == null) {
		throw new IllegalArgumentException("Invalid Client Registration with Id: " + registrationId);
	}
	
	/**
	  * Create {@code Oauth2AuthorizationRequest}'s extra attributes 
	  * via {@code ClientRegistration} and attributes
	  * in {@code HttpServletRequest}
	  */
	Map<String, Object> attributes = new HashMap<>();
	
	attributes.put(OAuth2ParameterNames.REGISTRATION_ID, clientRegistration.getRegistrationId());
	

	// builder of OAuth2AuthorizationRequest
	OAuth2AuthorizationRequest.Builder builder = getBuilder(clientRegistration, attributes);

	/****
	  * Expand RedirectUri 
	  * (e.g. Attributes in HttpServletRequest + Client Registration)
	  */
	String redirectUriStr = expandRedirectUri(request, clientRegistration, redirectUriAction);


	/**
	  * Build up a Auth2AuthorizationRequest
	  */
	builder.clientId(clientRegistration.getClientId()) // this authorizedRequest belongs who 
		   .authorizationUri(clientRegistration.getProviderDetails().getAuthorizationUri()) // authorized endpoint
		   .redirectUri(redirectUriStr)  // redirect endpoint (with scope, state) to the user 
		   .scopes(clientRegistration.getScopes()) 
		   .state(this.stateGenerator.generateKey())
		   .attributes(attributes);   //  attributes ( registration id, ... etc ...)
	
	// Accept the Customized authorization request 
	this.authorizationRequestCustomizer.accept(builder);
	
	return builder.build();
}
```

#### `expandRedirectUri` 

Generate Expand Redirect URI (e.g. URI from `ClientRegistration` + `HttpServletRequest`'s Attributes)   
```java
/**
 * Expands the {@link ClientRegistration#getRedirectUri()} with following provided variables:
 * <li> baseUrl (e.g. https://localhost/app)            </li>
 * <li> baseScheme (e.g. https)                         </li>      
 * <li> baseHost (e.g. localhost)                       </li>
 * <li> basePort (e.g. :8080)                           </li>       
 * <li> basePath (e.g. /app)                            </li> 
 * <li> registrationId (e.g. google, github ...)        </li> 
 * <li> action (e.g. login)                             </li>
 * <li> Null variables are provided as empty string     </lI>
 * 
 * @param request Attributes for expanding
 * @param clientRegistration get default redirect uri
 * @param action action for redirect Uri
 * 
 * Default redirectUri is: 
 * org.springframework.security.config.oauth2.client.CommonOAuth2Provider#DEFAULT_REDIRECT_URL
 */
private static String expandRedirectUri(
	HttpServletRequest request, 
	ClientRegistration clientRegistration,
	String action) {
	
    /**
	 * new a Map<String,String> HashMap instance 
     * to store attributes from 
	 * HttpServletRequest
	 * and ClientRegistration
	 */
	Map<String, String> uriVariables = new HashMap<>();
	
    // store registrationId
    uriVariables.put("registrationId", 
					 clientRegistration.getRegistrationId());
	

	/**
	  * uri-components from HttpServletRequest 
	  */
	UriComponents uriComponents = UriComponentsBuilder
                                    .fromHttpUrl(
										// {@code UrlUtils} sort attributes in {@code HttpServletRequest}  
                                        UrlUtils.buildFullRequestUrl(request))
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
	uriVariables.put("action", (action != null) ? action : ""); // login , sign up etc ...
	

	return UriComponentsBuilder
			.fromUriString(
				// RedirectUri :{baseScheme}://{baseHost}{basePort}{basePath}.
				clientRegistration.getRedirectUri())
			// Expand with Attributes in HttpServletRequest
			// buildAndExpand(HashMap<T,K> httpServletRequestURIVariables)
		    .buildAndExpand(uriVariables)
			.toUriString();
}
```

### `UrlUtil`

![image](https://user-images.githubusercontent.com/68631186/122837983-a7f57a00-d327-11eb-91c6-beef66472fd6.png)     

Sort each attribute in a HttpServletRequest Url
```java
public final class UrlUtil{
	// ...
	
	/**
	 *  Get Attributes from {@code HttpServletRequest} 
	 */
	public static String buildRequestUrl(HttpServletRequest r) {
		return buildRequestUrl(r.getServletPath(), 
							   r.getRequestURI(), 
							   r.getContextPath(), 
							   r.getPathInfo(),
							   r.getQueryString());
	}

    //...
}
```

#### `HttpServletRequest#getRequestURI`

`HttpServletRequest#getRequestURI`'s return value contains `protocol`, `server name`, `port` ,`number`, and `server path` (no query parameters included)

```java
public interface HttpServletRequest extends ServletRequest {

    //....

    /**
     * To reconstruct an URL with a scheme and host
     * Return the part of this request's URL from the protocol
     * 	   name up to the query string in the first line of the HTTP request. 
     * The web container does not decode this String. 
     *
     * For example Return Value
     * POST  /some/path.html       HTTP/1.1   => /some/path.html
     * GET   http://foo.bar/a.html HTTP/1.0   => /a.html
     * HEAD  /xyz?a=b              HTTP/1.1	  => /xyz
     *
     * @return {@code String} containing
     *	       the part of the URL from the
     *	       protocol name up to the query string
     */
    public String getRequestURI();

    /**
     * with {@code StringBuffer} the URL can be easily modified 
	 * for example, {@code append(String)} query parameters. 
     *
     * This method is useful for creating redirect messages
     * and for reporting errors.
	 *
     * @return a <code>StringBuffer</code> object containing
     *	       the reconstructed URL
     */
    public StringBuffer getRequestURL();

     //...
}


public class HttpUtils {
   
   /**
     *	 
     * The returned URL contains a protocol, server name, port
     * number, and server path, but it does not include query
     * string parameters. </p>
     * 
     * @param req	a {@code HttpServletRequest} object
     * 
     * @return		a {@code StringBuffer} object containing
     *			the reconstructed URL
     */
    public static StringBuffer getRequestURL (HttpServletRequest req) {
    
        StringBuffer url = new StringBuffer();
	
        String scheme  = req.getScheme ();    // http, https
        int port       = req.getServerPort ();
        String urlPath = req.getRequestURI();

        //String servletPath = req.getServletPath ();
        //String pathInfo = req.getPathInfo ();

        url.append (scheme);  
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

### `OAuth2AuthorizationRequest#getGrantType()`
- [forward and sendRedirect](https://stackoverflow.com/questions/20371220/what-is-the-difference-between-response-sendredirect-and-request-getrequestdis)  

```java
/**
  * Saving {@code #Oauth2AuthorizationRequest} 
  * via {@code #AuthorizationRequestRepository} (SESSION)
  * 
  * user-agent redirect via 
  * {@code AuthorizationRedirectStrategy#sendRedirect(HttpServletRequest, 
  *                                                   HttpServletResponse, 
  *                                                   authorizationRequest.getAuthorizationRequestUri()) 
  */
private void sendRedirectForAuthorization(HttpServletRequest request,
										  HttpServletResponse response,
                                          OAuth2AuthorizationRequest authorizationRequest) throws IOException {

    // check the Authorization Grant Type
    if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationRequest.getGrantType())) {
    	
		// save the request payloads (state, url ,... etc ) in http session
        this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, request, response);
    }
    
    /**
     * {@code authorizationRedirectStrategy} is {@code DefaultRedirectStrategy} type
     */
    this.authorizationRedirectStrategy.sendRedirect(request, response, authorizationRequest.getAuthorizationRequestUri());
}

// DefaultRedirectStrategy#sendRedirect
// response url = request#getContextPath + authorizationRequest#getAuthorizationRequestUri
public void sendRedirect(HttpServletRequest request, 
                         HttpServletResponse response,
                         String url) throws IOException {

    String redirectUrl = calculateRedirectUrl(request.getContextPath(), url);

    redirectUrl = response.encodeRedirectURL(redirectUrl);
    
    if (logger.isDebugEnabled()) {
        logger.debug("Redirecting to '" + redirectUrl + "'");
    }
    
	response.sendRedirect(redirectUrl);
}
```

## OAuth2LoginAuthenticationFilter

- [`OAuth2LoginAuthenticationFilter`](https://zhuanlan.zhihu.com/p/100625981) 

If they are valid then the filter returns `access_token` url 
- Client uses access token and calls (its spring api) `Oauth2UserService` to get third party protected resource for returning instance of `Authenttication` 
- `SecurityContextPersistenceFilter` will store protected resource in the local http session  (local endpoint) after that 

![image](https://user-images.githubusercontent.com/68631186/122872974-cd07de00-d363-11eb-88a4-67edc7b91d04.png)   

- An implementation of an {@link AbstractAuthenticationProcessingFilter} for OAuth 2.0 Login.

After that it generates a Authenticated `OAuth2LoginAuthenticationToken` to associated `Oauth2AuthorizedClient` and
save it in the {@code SecurityContextRepository} and {@code OAuth2AuthorizedClientRepository}
and delegates it to the  {@code AuthenticationManager} to make a authentication by creating a valid {@code OAuth2LoginAuthenticationToken} 

The OAuth 2.0 Authorization Response is processed as follows:

1. Checking The Grant Code and State from Client  
IF the End-User (Resource Owner) has granted access to the Client, the Authorization Server will append the  `OAuth2ParameterNames#CODE` and `OAuth2ParameterNames#STATE` attributes to the `OAuth2ParameterNames#REDIRECT_URI` (the one provided in the `auth2AuthorizedRequest`) and redirect the End-User's user-agent back to `OAuth2LoginAuthenticationFilter`

2. Generate the Token to client   
This filter will then create an `OAuth2LoginAuthenticationToken` with the `OAuth2ParameterNames#CODE` and delegate it to `AuthenticationManager` for authenticating

1. Save A Authorized Client in third party application   
Upon a successful authentication, an `OAuth2AuthenticationToken` is created (representing the End-User `Principal`)

1. Save (3rd party Application) the user principal in the client session    
Finally, the `OAuth2AuthenticationToken` is returned and ultimately stored in `SecurityContextRepository` to complete the authentication processing.

```java
public class OAuth2LoginAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	// Default_url, and Static final String attributes ....
	
	private ClientRegistrationRepository clientRegistrationRepository;
	private OAuth2AuthorizedClientRepository authorizedClientRepository;
	private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository = 
							new HttpSessionOAuth2AuthorizationRequestRepository();

    // other methods ....
	
	// Execute the Authentication for what the user gave from the client 
	// (password, email, state , scope ... etc  )
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
		 * Intercept the {@code Oauth2AuthorizationRequest} from Authorization Server
		 */
		OAuth2AuthorizationRequest authorizationRequest = 
						this.authorizationRequestRepository.removeAuthorizationRequest(request, response);
		if (authorizationRequest == null) {
			OAuth2Error oauth2Error = new OAuth2Error(AUTHORIZATION_REQUEST_NOT_FOUND_ERROR_CODE);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}
		
		/**
		 * Find the legit client from Authentication Server via 
		 * {@code authorizationRequest} and {@code clientRegistrationRepository}
		 * @throws Oauth2AuthenticationException
		 */
		String registrationId = authorizationRequest.getAttribute(OAuth2ParameterNames.REGISTRATION_ID);
		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
		if (clientRegistration == null) {
			OAuth2Error oauth2Error = new OAuth2Error(CLIENT_REGISTRATION_NOT_FOUND_ERROR_CODE,
					"Client Registration not found with Id: " + registrationId, null);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}
		
		/**
		 *  get Attributes from {@code HttpServletRequest}
		 *  By converting {@code HttpServletRequest} to Url
		 *  via {@code UriComponentsBuilder} to get each attribute
		 */
		String redirectUri = UriComponentsBuilder
								.fromHttpUrl(
									UrlUtils.buildFullRequestUrl(request))
								.replaceQuery(null)
								.build()
								.toUriString();
				
		/**
		  * Create authorization Response
		  */
		OAuth2AuthorizationResponse authorizationResponse = OAuth2AuthorizationResponseUtils.convert(params,redirectUri);
		
		Object authenticationDetails = this.authenticationDetailsSource.buildDetails(request);
		
		// 建立含有token的Authentication Request
		OAuth2LoginAuthenticationToken authenticationRequest = new OAuth2LoginAuthenticationToken(clientRegistration,
				new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse));
		
		authenticationRequest.setDetails(authenticationDetails);
		
		// AuthenticationManager authenticates authenticationRequest
		OAuth2LoginAuthenticationToken authenticationResult = (OAuth2LoginAuthenticationToken) 
				this.getAuthenticationManager().authenticate(authenticationRequest);
		
		// 建立代表該User的AuthenticationToken
		OAuth2AuthenticationToken oauth2Authentication = new OAuth2AuthenticationToken(
				authenticationResult.getPrincipal(), authenticationResult.getAuthorities(),
				authenticationResult.getClientRegistration().getRegistrationId());
				
		oauth2Authentication.setDetails(authenticationDetails);
		
		// 把Toke存入Authorization Server對應的Client中
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
				authenticationResult.getClientRegistration(), 
				oauth2Authentication.getName(),
				authenticationResult.getAccessToken(), 
				authenticationResult.getRefreshToken());
		this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, oauth2Authentication, request, response);
		
		return oauth2Authentication;
	}
}
```

#### removeAuthorizationRequest

```java 
@Override
public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request) {

	Assert.notNull(request, "request cannot be null");

	String stateParameter = this.getStateParameter(request);
	if (stateParameter == null) {
		return null;
	}
	
	// Map<"state", state_code> 
	Map<String, OAuth2AuthorizationRequest> authorizationRequests = this.getAuthorizationRequests(request);
	
	// get Oauth2AuthorizationRequest ("state" attribute)
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


private Map<String, OAuth2AuthorizationRequest> getAuthorizationRequests(HttpServletRequest request) {

		// Return a session only if there is one associated with the request (if not then don't create new session automatically)
		HttpSession session = request.getSession(false);
		
		Object sessionAttributeValue = (session != null) ? session.getAttribute(this.sessionAttributeName) : null;
		if (sessionAttributeValue == null) {
			return new HashMap<>();
		}
		
		else if (sessionAttributeValue instanceof OAuth2AuthorizationRequest) {
			// get Oauth2AuthorizationRequest's attribute `state`
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
	
	// get attributes (grant code, state, Error ... ) from MultiValueMap<String, String> reques
	static OAuth2AuthorizationResponse convert(MultiValueMap<String, String> request, String redirectUri) {
			
			String code = request.getFirst(OAuth2ParameterNames.CODE);
			String errorCode = request.getFirst(OAuth2ParameterNames.ERROR);
			String state = request.getFirst(OAuth2ParameterNames.STATE);
			

			// request has the grant code
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
	      								   .getAuthorizationRequest()
										   .getScopes()
										   .contains("openid")) {


	      return null;
	    }

	    OAuth2AccessTokenResponse accessTokenResponse;

	    try {
			OAuth2AuthorizationExchangeValidator.validate(
		    authorizationCodeAuthentication.getAuthorizationExchange())
			
			
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

1. `OAuth2AuthorizationRequestResolver` resolves the (`HttpServletRequest`) request from client.   
If the httpServletRequest `!= null`, it returns an instance of `OAuth2AuthorizationRequest` including `client_id`, `state`, `redirect_uri` ...

2. Store the valid `OAuth2AuthorizationRequest` via `authorizationRequestRepository.saveAuthorizationRequest` to the client's(spring application) session 
   > Authorization Server can look up authorization request's attribute `state` in the httpSession to compare with `state` from client's request to prevent the csrf attack

3. (If retured `OAuth2AuthorizationRequest` instance is not `null`)，filter will call `response.sendRedirect` method (to the Authorized Endpoint)
   > `OAuth2AuthorizationRequest` sent the frontend's response to redirect browser to the authorized page for the user entering password/email ..etc to be authenticated by Loginfilter
