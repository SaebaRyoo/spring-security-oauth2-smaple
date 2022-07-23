package com.mall.oauth.service;

import com.mall.oauth.pojo.User;
import com.mall.oauth.utils.UserJwt;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;


/**
 * 自定义授权认证类
 */
@Service(value = "customUserDetailsService")
public class CustomUserDetailsService implements UserDetailsService {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(11);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (!StringUtils.hasLength(username)) {
            return null;
        }

        //Test data
        //生产环境需要连接你的用户表
        User user = new User();
        user.setUsername("admin");
        user.setPassword("$2a$10$I.JQGDyCrFVrCDN.4yLGJOmO30dhBePqgv3Hm08dsjBgOHE6AktH."); // 密码是123
        String pwd = user.getPassword();
        //创建User对象
        String permissions = "user,vip"; // 指定用户的角色信息
        UserJwt userDetails = new UserJwt(username, pwd, AuthorityUtils.commaSeparatedStringToAuthorityList(permissions));
        return userDetails;
    }
}
