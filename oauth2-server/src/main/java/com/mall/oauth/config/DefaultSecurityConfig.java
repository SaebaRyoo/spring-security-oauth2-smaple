package com.mall.oauth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class DefaultSecurityConfig {
    private CustomAuthenticationProvider customAuthenticationProvider;

    @Autowired
    public void setCustomAuthenticationProvider(CustomAuthenticationProvider customAuthenticationProvider) {
        this.customAuthenticationProvider = customAuthenticationProvider;
    }

    /**
     * Then we'll enable the Spring web security module with an @EnableWebSecurity annotated configuration class:
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    public SecurityFilterChain standardSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated()  //其他请求都需要经过验证
                )
                .authenticationProvider(customAuthenticationProvider)
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

}
