# Oauth2 LogIn WebSecurity Configuration
- [Protocol Endpoints](https://datatracker.ietf.org/doc/html/rfc6749#section-3)  
- [Configure the authorization of the ROLE](https://stackoverflow.com/questions/36233910/custom-http-security-configuration-along-with-oauth2-resource-server)

## SetUp

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

![image](https://user-images.githubusercontent.com/68631186/122627719-db47c700-d0e3-11eb-9c9b-9c8f3743c623.png)  
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
- (Authorization Server's) Authorization Endpoint  
Where client can obtain authorization grant issued by the resource owner via user-agent redirection. (e.g. Login via the user's 3rd application account)
	- Authorization Server issues Authorization Grant (intercepted by `OAuth2AuthorizationRequestRedirectFilter`)
	- Client receives Authorization Grant(intercepted by `LoginAuthenticationFilter`)
	
- (Client's) Redirection Endpoint  
after authorization grant flow, Authentication Server returns responses containing authorization credentials to the client via the resource owner's user-agent. 

- (Authorization Server's) Token Endpoint  
Where client exchange an authorization grant for an access token/refresh token, typically with client authentication. 

- The UserInfo Endpoint   
**Protected Resource** that returns claims about the authenticated end-user (**Instance of `Authentication`**). 
  > The client makes a request to the UserInfo Endpoint by using an access token obtained through OpenID Connect Authentication (Authorization Server). 
  >> These claims are normally represented by a `JSON` object that contains a collection of `name-value` pairs for the claims.

## Login Flow In Action

The OAuth2 login flow will be initiated by the client while sending the user to `http://localhost:8080/oauth2/authorize/{provider}?redirect_uri=<redirect_uri_after_login>`.
- The `{provider}` parameter is one of `GOOGLE`,`GITHUB` or other third party application. 
- The `redirect_uri` is the URI where the resource owner's user-agent redirects once the authorization is granted successfully. (e.g. `localhost:4200/oauth2/`)

On receiving the `OAuth2AuthorizationRequest` object, Client(Spring API) will redirect the user to the (Authorized Endpoint) Authorization Url of the supplied provider.
- All the states (attributes from `HttpServletRequest`) associated/related to the authorization request(`OAuth2AuthorizationRequest` object) is saved via `authorizationRequestRepository` repository specified in the SecurityConfig.
 
##### IF    
the user grants authorization to the client(log in 3rd party application successfully), the user-agent redirect to the callback url `http://localhost:8080/oauth2/callback/{provider}` with query parameters (e.g. `state` , `code`,    `redirect_url`). 

> **callback url contains the authorization code, so client('s Spring Security API) will exchange the authorization code for an access_token**    

client then uses the `OAuth2UserService` to retrieve protected resource and creates a new entry in the database or updates the existing entry.   

Upon a successful authentication, the `oAuth2AuthenticationSuccessHandler` is invoked.    

> We also can create a JWT authentication token for the user by putting `redirect_uri` along with the JWT token in a query string. (e.g. `frontend:/oauth2/?token= ...`)

##### ELSE   
It redirects to `http://localhost:8080/oauth2/callback/{provider}` with an `error` query parameter
- Spring security will invoke the `oAuth2AuthenticationFailureHandler` specified in the above SecurityConfig


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
- Must provide a `@Controller` class with a `@RequestMapping("/login/oauth2")` that is capable of rendering the custom login page.
- Configuring `oauth2Login().authorizationEndpoint().baseUri()` is OPTIONAL. However, if you choose to customize it, ensure the link to each OAuth Client matches the `authorizationEndpoint().baseUri()`.

## Redirection Endpoint

**The Redirection Endpoint is used by the Authorization Server for returning the Authorization Response** (which contains the authorization credentials and will be intercepted by the `LoginAuthenticationFilter`) to the client

The default Authorization Response baseURI
```
/login/oauth2/code/*
```

### Configure Redirect URI

We can customize it to any other URL of our choice 
for example 
```
/oauth2/callback/
```

Set Up Redirect URI In `application.properties`
```xml
spring.security.oauth2.client.registration.google.redirect-uri=http://localhost:8080/oauth2/callback/google
```

Configure it in HttpSecurity via `http.redirectionEndpoint().baseUri(....)`
```java
protected void configure(HttpSecurity http) throws Exception {
	http.authorizeRequests()
			.anyRequest().authenticated()
        .and()
        .oauth2Login()
            .redirectionEndpoint().baseUri(
				"login/oauth2/callback/*");
}
```

## UserInfo Endpoint  

It retrieve the authenticated Oauth2User resource

The UserInfo Endpoint includes a number of configuration options
- Mapping Authenticated User from 3rd Party Authorities for this application
- Configuring a Custom OAuth2User
- OAuth 2.0 UserService
- OpenID Connect 1.0 UserService

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
http.oauth2Login()
   	.userInfoEndpoint()
	   // set up the Authorities of this application
	   .userAuthoritiesMapper(
		   this.userAuthoritiesMapper())    
		// retrieve the authenticated user 
		// resource from third party
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


## OAuth2's UserService Configuration

`OAuth2UserRequest` (and `OidcUserRequest`) provides you access to the associated `OAuth2AccessToken`, which is very useful in the cases where the delegator needs to **fetch authority information from a protected resource** before it can map the custom authorities for the user.

that's why it configure OAuth2's UserService like this
```java
http.userInfoEndpoint()
		.userService(this.oauth2UserService())
		.oidcUserService(this.oidcUserService())
``` 

```java
private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() 
{
	final OidcUserService delegate = new OidcUserService();
	
	return (userRequest) -> {
		
		// Delegate to the Default 
		// implementation (OidcUserService)
		// for loading an authenticated user
		OidcUser oidcUser = 
				delegate.loadUser(userRequest);
		
		// Fetch Access Token 
		// band Assign to {@code Oauth2AccessToken}
		OAuth2AccessToken accessToken =
				 userRequest.getAccessToken();
		
		Set<GrantedAuthority> mappedAuthorities = 
				new HashSet<>();

		/**
		* Fetch the authority information 
		*     from the protected resource 
		*     using accessToken 
		*     VIA {@code odcUser.getIdToken()}
		* Map the Authority Information 
		*     to one or more GrantedAuthority's 
		*     and add it to mappedAuthorities 
		*     VIA {@code oidcUser.getUserInfo()}
		* Create a copy of {@code oidcUser} 
		*     but use the mappedAuthorities instead
		*/
		oidcUser = new DefaultOidcUser(
						mappedAuthorities, 
						oidcUser.getIdToken(), 
						oidcUser.getUserInfo()
		);
			
		return oidcUser;
	};
}
```

### Default Oauth2User

## Oauth2User Provider

Oauth2User has default provider called `CommonOAuth2Provider`
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


### Self-Defined Oauth2User(principal)
If the default implementation `DefaultOAuth2User` does not suit your needs, you can define your own implementation of `OAuth2User`.

For example creating a custom Oauth2User principal for github

```java
public class GitHubOAuth2User implements OAuth2User {

    // We often override getAuthorities() and getAttributes()
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

Configure it in HttpSecurity
```java
@Override
protected void configure(HttpSecurity http) throws Exception {
	http
		.oauth2Login()
			.userInfoEndpoint()
				.customUserType(
					GitHubOAuth2User.class, 
					"github")
		//.......
}
```

### Self-Defined Oauth2 UserService

A `DefaultOAuth2UserService` is an implementation of an `OAuth2UserService` that supports standard OAuth 2.0 Provider’s.   

```java
//...

@Override
protected void configure(HttpSecurity http) throws Exception {
    http
        .oauth2Login()
            .userInfoEndpoint()
                .userService(this.oauth2UserService())
			//...
}

private OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {
    return new CustomOAuth2UserService();
}
```
- `OAuth2UserService` obtains the user attributes of the end-user from the UserInfo Endpoint.  
It returns an Authenticated `principal` in the form of an `OAuth2User`.

A self-defined OAuth2 UserService Implementation looks like this way
```java
@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService{

  @Autowired
  private UserRepository userRepository;
    
  //..

  @Override
  public OAuth2User loadUser(
	  OAuth2UserRequest oAuth2UserRequest) 
	  throws OAuth2AuthenticationException {
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
		    	.accessTokenResponseClient(
					this.accessTokenResponseClient())
	    
      //...
}

private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
	return new SpringWebClientAuthorizationCodeTokenResponseClient();
}
```
