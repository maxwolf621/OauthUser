package com.githublogin.demo.service;

import java.util.Collection;


import com.githublogin.demo.model.User;
import com.githublogin.demo.repository.UserRepository;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import lombok.AllArgsConstructor;
import static java.util.Collections.singletonList;


/* Problem
 * https://stackoverflow.com/questions/49715769/why-is-my-oauth2-config-not-using-my-custom-userservice
 *
 */

@Service
@AllArgsConstructor
public class UserPrincipalService implements UserDetailsService{
    private final UserRepository userRepo;

    // customize provider fetch user details
    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String UserName) throws UsernameNotFoundException {
        User user = userRepo.findByUsername(UserName).orElseThrow(() -> new UsernameNotFoundException("No user " + "Found with username : " + UserName)); 
        /** 
         * User https://github.com/spring-projects/spring-security/blob/main/core/src/main/java/org/springframework/security/core/userdetails/User.java
         * Return Principal (The Authenticated User)
         * public User(String username, 
         *             String password, 
         *             boolean enabled, 
         *             boolean accountNonExpired,
         *             boolean credentialsNonExpired, 
         *             boolean accountNonLocked,
         *             Collection<? extends GrantedAuthority> authorities)
         */
        return new org.springframework.security.core.userdetails.User(
                                        user.getUsername(), 
                                        user.getPassword(),
                                        user.isLegit(), 
                                        true,
                                        true,
                                        true, 
                                        this.getAuthorities("USER")
                                        );
    }
    
    private Collection<? extends GrantedAuthority> getAuthorities(String role) {
        //This method returns an immutable list containing only the specified object
        return singletonList(new SimpleGrantedAuthority(role));
    }

}
