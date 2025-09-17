package org.javaboy.authserver.config;

import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @author shuxian
 * @date 2025-09-15
 * @description
 */
@Component
public class CustomJwtAccessTokenConverter extends JwtAccessTokenConverter {

    private static final String ISSUER = "https://auth.yourgameplatform.com";
    private static final String AUDIENCE = "resource-api";


    private static final String SIGNING_KEY = "my-super-long-and-secure-signing-key!";

    public CustomJwtAccessTokenConverter() {
        // 使用对称密钥（HMAC 签名）
        String signingKey = SIGNING_KEY;
        setSigningKey(signingKey);  // 直接设置字符串密钥
    }

    @Override
    public Map<String, ?> convertAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
        Map<String, Object> representation = new LinkedHashMap<>(
                super.convertAccessToken(token, authentication));

        //todo 未生效，添加 iss（签发者） 和 aud（token的受众，可以访问哪些资源）
        representation.put("iss", ISSUER);
        representation.put("aud", AUDIENCE);

        // 可选：添加 nbf
        representation.put("nbf", System.currentTimeMillis() / 1000);

        return representation;
    }
}
