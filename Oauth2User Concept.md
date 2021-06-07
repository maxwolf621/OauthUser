

[More Details](https://datatracker.ietf.org/doc/html/rfc6749#section-1.1)
[Good Explanation](http://www.ruanyifeng.com/blog/2019/04/oauth-grant-types.html)
# Protocol Flow 

1. Request For The Permission
    > Client Requests Resource Owner the Authorization Grant
(A permission)

(If Resource Owner grants the Permission for the client)

2. Request For The Token via the grant
    > The client requests an access token by authenticating with the authorization server and presenting the authorization grant.

3. Request For the Proteted Resource (e.g. User Detail Information) via the token
    > The client requests the protected resource from the resource server and authenticates by presenting the access token.

###  Authorization Grant

An authorization grant is a credential representing the resource owner's authorization (to access its protected resources) used by the client to obtain an access token.  

This specification defines four grant types
1. authorization code
2. implicit
3. resource owner password credentials
4. client credentials 


