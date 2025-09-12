//package org.javaboy.client2.config;
//
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.oauth2.provider.token.TokenStore;
//import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
//import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
//
///**
// * @author shuxian
// * @date 2025-09-11
// * @description
// */
//
//
////@Configuration
////public class AccessTokenConfig {
////    private static final String SIGNING_KEY = "my-super-long-and-secure-signing-key!";
////    @Bean
////    TokenStore tokenStore() {
////        return new JwtTokenStore(jwtAccessTokenConverter());
////    }
////
////    @Bean
////    JwtAccessTokenConverter jwtAccessTokenConverter() {
////        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
////        converter.setSigningKey(SIGNING_KEY);
////        return converter;
////    }
////}
