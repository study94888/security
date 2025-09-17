package org.javaboy.authserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * @author shuxian
 * @date 2025-09-11
 * @description
 */


@Configuration
public class AccessTokenConfig {
    private static final String SIGNING_KEY = "my-super-long-and-secure-signing-key!";
    @Bean
    TokenStore tokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    @Bean
    JwtAccessTokenConverter jwtAccessTokenConverter() {
        System.out.println("✅ 使用新密钥创建 JwtAccessTokenConverter: " + SIGNING_KEY);
        JwtAccessTokenConverter converter = new CustomJwtAccessTokenConverter();
        converter.setSigningKey(SIGNING_KEY);
        System.out.println("Key bytes: " + Arrays.toString(SIGNING_KEY.getBytes(StandardCharsets.UTF_8)));
        System.out.println("Key length: " + SIGNING_KEY.getBytes(StandardCharsets.UTF_8).length);

        return converter;
    }
}
