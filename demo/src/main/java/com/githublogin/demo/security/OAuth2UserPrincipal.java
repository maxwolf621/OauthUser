package com.githublogin.demo.security;

import org.springframework.security.oauth2.core.user.OAuth2User;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import com.githublogin.demo.oauth2userinfo.OAuth2UserInfo;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.util.Assert;


/**
 1. Return A Custom Authentication 
 2. This Model used by Custom Oauth2User Service
 */
public class OAuth2UserPrincipal implements OAuth2User, Serializable {
    
    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
	private final Set<GrantedAuthority> authorities;
	private final Map<String, Object> attributes;
	private final String nameAttributeKey;
    private final OAuth2UserInfo userInfo;


    public OAuth2UserPrincipal(Collection<? extends GrantedAuthority> authorities, 
                               Map<String, Object> attributes,
                               String nameAttributeKey /* user name */,
                               OAuth2UserInfo userInfo) {
        /**
         * Assert 
            '--> Attributes 
            '--> Attribute 'name' contains in Attributes
        */
        Assert.notEmpty(attributes, "attributes cannot be empty");
        Assert.hasText(nameAttributeKey, "nameAttributeKey cannot be empty");
        if (!attributes.containsKey(nameAttributeKey)) {
            throw new IllegalArgumentException("Missing attribute '" + nameAttributeKey + "' in attributes");
        }

        this.authorities = (authorities != null)
                ? Collections.unmodifiableSet(new LinkedHashSet<>(this.sortAuthorities(authorities)))
                : Collections.unmodifiableSet(new LinkedHashSet<>(AuthorityUtils.NO_AUTHORITIES));
        
        this.attributes = Collections.unmodifiableMap(new LinkedHashMap<>(attributes));
        this.nameAttributeKey = nameAttributeKey;
        this.userInfo = userInfo;
    }


    // Get UserName
    @Override
	public String getName() {
		return this.getAttribute(this.nameAttributeKey).toString();
	}

    // Get Authorities ("ROLE_USER")
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return this.authorities;
	}

    // Get Attributes from ThirdParty Application
	@Override
	public Map<String, Object> getAttributes() {
		return this.attributes;
	}

	private Set<GrantedAuthority> sortAuthorities(Collection<? extends GrantedAuthority> authorities) {
		SortedSet<GrantedAuthority> sortedAuthorities = new TreeSet<>(
				Comparator.comparing(GrantedAuthority::getAuthority));
		sortedAuthorities.addAll(authorities);
		return sortedAuthorities;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || this.getClass() != obj.getClass()) {
			return false;
		}
		OAuth2UserPrincipal that = (OAuth2UserPrincipal) obj;
		if (!this.getName().equals(that.getName())) {
			return false;
		}
		if (!this.getAuthorities().equals(that.getAuthorities())) {
			return false;
		}
		return this.getAttributes().equals(that.getAttributes());
	}

	@Override
	public int hashCode() {
		int result = this.getName().hashCode();
		result = 31 * result + this.getAuthorities().hashCode();
		result = 31 * result + this.getAttributes().hashCode();
		return result;
	}

    public OAuth2UserInfo getUserInfo(){
        return this.userInfo; 
    }

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("Name: [");
		sb.append(this.getName());
		sb.append("], Granted Authorities: [");
		sb.append(getAuthorities());
		sb.append("], User Attributes: [");
		sb.append(getAttributes());
		sb.append("]");
		return sb.toString();
    }
}
