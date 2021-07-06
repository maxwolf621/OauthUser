package com.githublogin.demo.oauth2userinfo;

import java.util.Map;

import com.githublogin.demo.model.AuthProviderType;

public class GitHubUserInfo extends OAuth2UserInfo {

    
    /** 
     --------------------- Attributes ---------------------
        login=maxwolf621, 
        id= .... , 
        node_id= ... , 
        avatar_url=https://avatars.githubusercontent.com/ .... , 
        gravatar_id=, 
        url=https://api.github.com/users/maxwolf621, 
        html_url=https://github.com/maxwolf621, 
        followers_url=https://api.github.com/users/maxwolf621/followers, 
        following_url=https://api.github.com/users/maxwolf621/following{/other_user}, 
        gists_url=https://api.github.com/users/maxwolf621/gists{/gist_id}, 
        starred_url=https://api.github.com/users/maxwolf621/starred{/owner}{/repo}, 
        subscriptions_url=https://api.github.com/users/maxwolf621/subscriptions, 
        organizations_url=https://api.github.com/users/maxwolf621/orgs, 
        repos_url=https://api.github.com/users/maxwolf621/repos, 
        events_url=https://api.github.com/users/maxwolf621/events{/privacy}, 
        received_events_url=https://api.github.com/users/maxwolf621/received_events, 
        type=User, 
        site_admin=false, 
        name=maxwolf621, 
        company=null, 
        blog=, 
        location=null, 
        email=null, 
        hireable=null, 
        bio=null, 
        twitter_username=null, 
        public_repos=13, 
        public_gists=0, 
        followers=0, 
        following=0, 
        created_at=2020-07-22T05:37:14Z, 
        updated_at=2021-06-30T05:45:40Z, 
        private_gists=1, 
        total_private_repos=4, 
        owned_private_repos=4, 
        disk_usage=5762, 
        collaborators=0, 
        two_factor_authentication=false, 
        plan={name=free, space=976562499, collaborators=0, private_repos=10000}
     */
    public GitHubUserInfo(Map<String, Object> claims){
        super(claims);
    }

    private final AuthProviderType authProvider = AuthProviderType.GITHUB;

    @Override
    public AuthProviderType getAuthProvider(){
        return authProvider;
    } 

    @Override
    public String getId() {
        return ((Integer) attributes.get("id")).toString();
    }

    @Override
    public String getUsername() {
        return (String) attributes.get("name");
    }

    @Override
    public String getEmail() {
        String email = (String) attributes.get("email");
        return email;
    }
}
