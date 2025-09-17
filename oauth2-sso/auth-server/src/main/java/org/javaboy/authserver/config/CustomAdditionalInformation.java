package org.javaboy.authserver.config;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;

/**
 * @author shuxian
 * @date 2025-09-11
 * @description
 */
@Component
public class CustomAdditionalInformation implements TokenEnhancer {

    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken,
                                     OAuth2Authentication authentication) {

        Map<String, Object> info = new HashMap<>();

        Map<String, Object> userInfoMap = new HashMap<>();
        userInfoMap.put("user_name", authentication.getName());
        userInfoMap.put("avatar_url", "https://cdn.example.com/avatar/" + authentication.getName() + ".png");
        userInfoMap.put("level", 35);           // 可根据用户等级查询
        userInfoMap.put("vip_level", 2);
        userInfoMap.put("region", "shanghai");
        // authorities（Spring Security 使用）
        Collection<? extends GrantedAuthority> authorities = authentication.getUserAuthentication().getAuthorities();
        List<String> authorityList = authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        userInfoMap.put("authorities", authorityList);
        info.put("userInfo", userInfoMap);

        Map<Object, Object> clientMap = new HashMap<>();
        clientMap.put("client_id", authentication.getOAuth2Request().getClientId());
        clientMap.put("scope", accessToken.getScope());
        clientMap.put("company", "yk-game-platform");
        info.put("clientInfo", clientMap);

        String jti = UUID.randomUUID().toString();
        info.put("jti", jti);

        // ⚠️ 只设置额外信息
        DefaultOAuth2AccessToken customToken = new DefaultOAuth2AccessToken(accessToken);
        customToken.setAdditionalInformation(info); // 这些信息会被 JwtAccessTokenConverter 编码进 JWT
        return customToken;
    }
}

//@Component
//public class CustomAdditionalInformation implements TokenEnhancer {
//    @Override
//    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
//        Map<String, Object> info = accessToken.getAdditionalInformation();
//        System.out.println("info:"+info);
//        info.put("author", "江南一点雨");
//        ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(info);
//        return accessToken;
//    }
//}