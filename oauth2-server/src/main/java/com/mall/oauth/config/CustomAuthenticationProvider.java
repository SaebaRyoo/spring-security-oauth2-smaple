package com.mall.oauth.config;


import com.mall.oauth.service.CustomUserDetailsService;
import com.mall.oauth.utils.BCrypt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Collection;

@Component("AuthenticationProvider")
public class CustomAuthenticationProvider implements AuthenticationProvider {

    CustomUserDetailsService CustomUserDetailsService;

    @Autowired
    public void setUserDetailsService(com.mall.oauth.service.CustomUserDetailsService CustomUserDetailsService) {
        this.CustomUserDetailsService = CustomUserDetailsService;
    }


    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        UserDetails userDetails = CustomUserDetailsService.loadUserByUsername(username);

        if (userDetails == null || !userDetails.getUsername().equalsIgnoreCase(username)) {
            throw new BadCredentialsException("Username not found.");
        }

        //检查密码是否一致
        if (!BCrypt.checkpw(password, userDetails.getPassword())) {
            throw new BadCredentialsException("Wrong password.");
        }

        //TODO: 权限待实现
        //userDetails.getRoles();
        Collection<? extends GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList("user,admin");

        return new UsernamePasswordAuthenticationToken(userDetails, password, authorities);

    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }


}