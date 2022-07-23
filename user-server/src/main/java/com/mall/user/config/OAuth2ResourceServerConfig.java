package com.mall.user.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class OAuth2ResourceServerConfig {

    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    String jwkSetUri;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        //.antMatchers(HttpMethod.GET, "/message/**").hasAuthority("SCOPE_message:read")
                        //.antMatchers(HttpMethod.POST, "/message/**").hasAuthority("SCOPE_message:write")
                        //.mvcMatchers("/user/**").hasAuthority("SCOPE_message:read")
                        .mvcMatchers("/api/**").hasAuthority("SCOPE_api.read")
                        .anyRequest().authenticated()
                )
                //.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
                .oauth2ResourceServer()
                .jwt();

        return http.build();
    }

    @Bean
    JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withJwkSetUri(this.jwkSetUri).build();
    }

}
