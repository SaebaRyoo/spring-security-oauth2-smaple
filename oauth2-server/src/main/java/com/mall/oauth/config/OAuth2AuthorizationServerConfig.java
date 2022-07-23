/*
 * Copyright 2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.mall.oauth.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

/**
 * OAuth 认证服务器配置
 */
@Configuration
public class OAuth2AuthorizationServerConfig {

    @Value("${auth.clientId}")
    private String clientId;

    @Value("${auth.clientSecret}")
    private String clientSecret;

    PasswordEncoder passwordEncoder;

    @Autowired
    public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    //配置OAuth2授权服务其他默认配置
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        return http
                //对与未认证的授权请求，将该请求重定向到登录页面
                .exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
                //.httpBasic(Customizer.withDefaults())        //启用Http基本身份验证
                //.formLogin(Customizer.withDefaults()) // 启用表单身份验证
                //.authorizeRequests()    //限制基于Request请求访问
                //.and()
                .build();
    }


    /**
     * 在内存中配置一个用户，user/password分别是用户名和密码，这个用户拥有USER角色。
     * withDefaultPasswordEncoder 被遗弃，原因是不安全
     *
     * 这个只在测试环境用，生产环境中自定义了CustomUserDetailService方法来实现查询mall_user数据库中的tb_user表中的用户信息
     */
    //@Bean
    //public UserDetailsService userDetailsService() {
    //
    //    UserDetails userDetails = User.builder()
    //            .username("user")
    //            //.password("password")
    //            .password(passwordEncoder.encode("password"))
    //            .roles("USER")
    //            .build();
    //
    //    return new InMemoryUserDetailsManager(userDetails);
    //}

    /**
     * An instance of RegisteredClientRepository for managing clients.
     * @return
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                //唯一的客户端ID和密码
                .clientId(clientId)
                //	{noop} represents the PasswordEncoder id for Spring Security’s NoOpPasswordEncoder.
                //.clientSecret("{noop}dev")
                .clientSecret(passwordEncoder.encode(clientSecret))
                //授权方法
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                //授权类型
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS) //客户端认证
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE) // 授权码认证
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                //回调地址名单，不在此名单将被拒绝 只能使用IP或域名
                .redirectUri("http://127.0.0.1:9001/login/oauth2/code/api-client-oidc")
                .redirectUri("http://127.0.0.1:9001/authorized")
                .redirectUri("http://www.baidu.com")
                //其他scope
                .scope(OidcScopes.OPENID)
                .scope("api.read")
                //.scope("message:write")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                //.tokenSettings(
                //        TokenSettings.builder()
                //                .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
                //                .accessTokenTimeToLive(Duration.ofSeconds(30*60))
                //                .refreshTokenTimeToLive(Duration.ofSeconds(60*60))
                //                .reuseRefreshTokens(true)
                //                .build()
                //)
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    /**
     * JWK全称JSON Web Key。意义在于生成JWT和提供JWK端点给OAuth2.0资源服务器解码校验JWT。
     *	An instance of com.nimbusds.jose.jwk.source.JWKSource for signing access tokens.
     * @param keyPair
     * @return
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource(KeyPair keyPair) {
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic(); // 公钥
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate(); // 私钥
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    /**
     * 生成证书
     * An instance of java.security.KeyPair with keys generated on startup used to create the JWKSource above.
     */
    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    @Bean
    public JwtDecoder jwtDecoder(KeyPair keyPair) {
        return NimbusJwtDecoder.withPublicKey((RSAPublicKey) keyPair.getPublic()).build();
    }

    /**
     * An instance of ProviderSettings to configure Spring Authorization Server.
     * 配置 OAuth2.0 provider元信息
     * 客户端信息RegisteredClient包含了Token的配置项TokenSettings和客户端配置项ClientSettings。
     * 授权服务器本身也提供了一个配置工具来配置其元信息，大多数我们都使用默认配置即可，
     * TODO: 唯一需要配置的其实只有授权服务器的地址issuer，在生产中应该配置为域名。
     *
     * @return
     */
    @Bean
    public ProviderSettings providerSettings(@Value("${server.port}") Integer port) {
        return ProviderSettings.builder().issuer("http://localhost:" + port).build();
    }


}
