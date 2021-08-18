# OAuth2 endPoints 

```java
@EnableWebSecurity
public class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.oauth2Login()
				  .authorizationEndpoint()
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
- Authorization Endpoint
  > **Used by the client** to obtain authorization from the resource owner via user-agent redirection. 
- Token Endpoint
  > **Used by the client** to exchange an authorization grant for an access token, typically with client authentication. 
- Redirection Endpoint
  > **Used by the authorization** server to return responses containing authorization credentials to the client via the resource owner user-agent. 
- The UserInfo Endpoint : an OAuth 2.0 **Protected Resource(第三方網站的存取資源)** that returns claims about the authenticated end-user (**Instance of Authentication**). 
  > The client makes a request to the UserInfo Endpoint by using an access token obtained through OpenID Connect Authentication (Authorization Server). 
  >> These claims are normally represented by a `JSON` object that contains a collection of `name-value` pairs for the claims.


### A Custom Oauth2 Login Flow
 
1.The OAuth2 login flow will be initiated by the frontend client by sending the user to the endpoint 
 	> `http://localhost:8080/oauth2/authorize/{provider}?redirect_uri=<redirect_uri_after_login>`.
	> The `{provider}` path parameter is one of `GOOGLE`,`GITHUB` or other third party application. 
	> The `redirect_uri` is the URI to which the user will be redirected once the authentication with the OAuth2 provider is successful (login from third party application).

2. On receiving the `OAuth2AuthorizationRequest` object, Spring Security’s client(Our Spring Application) will redirect the user to the (Authorized Endpoint) AuthorizationUrl of the supplied provider.

3. All the state (attributes from `HttpServletRequest`) associated/related to the authorization request is saved using the `authorizationRequestRepository` specified in the SecurityConfig.

4. The user(you) now allows/denies permission to your app on the provider’s page. 
	 > If the user allows permission to the app(allowing to use third party account to login the app),   
	 > the provider will redirect the user to the callback url `http://localhost:8080/oauth2/callback/{provider}` with an authorization code.
	 > If the user denies the permission, he/her will be redirected to the same callbackUrl but with an `error` (more details on filter chapter).

5. If the OAuth2 callback results in an error, Spring security will invoke the `oAuth2AuthenticationFailureHandler` specified in the above SecurityConfig. Else If the OAuth2 callback is successful and it contains the authorization code, **Spring Security will exchange the authorization_code for an access_token and invoke the `customOAuth2UserService` specified in the the (httpScurity) SecurityConfig.**

6. The `customOAuth2UserService` retrieves the details of the authenticated user and creates a new entry in the database or updates the existing entry with the same email.

7. Upon a successful authentication, the `oAuth2AuthenticationSuccessHandler` is invoked. 
	 > It creates a JWT authentication token for the user and sends the user to the `redirect_uri` along with the JWT token in a query string.


## A custom Login Page

To override the default login page, configure `oauth2Login().loginPage()` and (OPTIONAL) `oauth2Login().authorizationEndpoint().baseUri().`
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
- Configuring `oauth2Login().authorizationEndpoint().baseUri()` is OPTIONAL. However, if you choose to customize it, ensure the link to each OAuth Client matches the `authorizationEndpoint().baseUri()`.

## redirection Endpoint

**The Redirection Endpoint is used by the Authorization Server for returning the Authorization Response** (which contains the authorization credentials and will be intercepted by the `LoginAuthenticationfilter`) to the client

The default Authorization Response baseUri
```diff
/login/oauth2/code/*
```

We can customize it to any other URL of our choice  for example `(/oauth2/callback/)`.  

Set A custom redirect-uri in `application.properties`
```xml
spring.security.oauth2.client.registration.google.redirect-uri=http://localhost:8080/oauth2/callback/google
```

Configure it in our spring security 
```java
protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
              .anyRequest().authenticated()
            .and()
            .oauth2Login()
              .redirectionEndpoint().baseUri("login/oauth2/callback/*");
    }
```

## UserInfo Endpoint (An AuthenticationManager)

It retrieve the authenticated Oauth2 User resource (第三方使用者的資源)

The UserInfo Endpoint includes a number of configuration options,
- Mapping Authenticated User from 3rd Party Authorities for this application
- Configuring a Custom OAuth2User
- OAuth 2.0 UserService
- OpenID Connect 1.0 UserService

```java
@Override
	protected void configure(HttpSecurity http) throws Exception {
		htt.oauth2Login()
		   .userInfoEndpoint()
		     // set up the Authorities of this application
         .userAuthoritiesMapper(this.userAuthoritiesMapper()) 
         
		     // retrieve the authentticated user resource from third party
         .userService(this.oauth2UserService())
		   .oidcUserService(this.oidcUserService())
	}
```


### Configure a custom `.userAuthoritiesMapper(this.userAuthoritiesMapper)` for Set of `GrantedAuthority` and User Info

After the user successfully authenticates with the OAuth 2.0 Provider, the `OAuth2User.getAuthorities()` (or `OidcUser.getAuthorities()`) may be mapped to a new set of GrantedAuthority instances, which will be supplied to `OAuth2AuthenticationToken` when completing the authentication.
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

### custom UserServer via `OAuth2UserRequest` and `OidcUserRequest` for `OAuth2AccessToken` and User Info

For configuring a custom`.userService(this.oauth2UserService())` or `.oidcUserService(this.oidcUserService())` with `OAuth2AccessToken`

The `OAuth2UserRequest` (and `OidcUserRequest`) provides you access to the associated `OAuth2AccessToken`, which is very useful in the cases where the delegator needs to **fetch authority information from a protected resource** before it can map the custom authorities for the user.

```java
	private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
		final OidcUserService delegate = new OidcUserService();

		return (userRequest) -> {
    
			// Delegate to the Default implementation for loading a user
			OidcUser oidcUser = delegate.loadUser(userRequest);

      // Fetch Access Token and Assign to {@code Oauth2AccessToken}
			OAuth2AccessToken accessToken = userRequest.getAccessToken();
      
			Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

			
      /**
        * <p> Fetch the authority information 
        *     from the protected resource 
        *     using accessToken VIA {@code odcUser.getIdToken()}
        * <p> Map the Authority Information to one or more GrantedAuthority's 
        *     and add it to mappedAuthorities VIA {@code oidcUser.getUserInfo()}
        * <p> Create a copy of {@code oidcUser} but use the mappedAuthorities instead </p>
        */
			oidcUser = new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());

			return oidcUser;
		};
	}
```

### Configure a Custom Implementation of Oauth2User for UserInfo

If the default implementation `DefaultOAuth2User` does not suit your needs, you can define your own implementation of `OAuth2User`.

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

### Configure a custom `.userService(this.OurCustomUserService())` for an UserInfo from 3rd party application

A `DefaultOAuth2UserService` is an implementation of an `OAuth2UserService` that supports standard OAuth 2.0 Provider’s.
> `OAuth2UserService` obtains the user attributes of the end-user from the UserInfo Endpoint (by using the access token granted to the client during the authorization flow) and returns an Authenticated Principal in the form of an OAuth2User.

In spring Security
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


A custom OAuth2 User Service setup
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

## Token Endpoint

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
