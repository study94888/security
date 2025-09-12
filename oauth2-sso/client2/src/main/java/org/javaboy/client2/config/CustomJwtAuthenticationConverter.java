package org.javaboy.client2.config;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Collection;
import java.util.stream.Collectors;

/**
 * @author shuxian
 * @date 2025-09-12
 * @description
 */
public class CustomJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final JwtAuthenticationConverter delegate = new JwtAuthenticationConverter();

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        // 1. 提取用户名：优先使用 user_name，否则用 sub
        String username = jwt.getClaim("user_name");
        if (username == null) {
            username = jwt.getSubject(); // fallback
        }

        // 2. 提取权限：支持自定义的 "authorities" 数组
        Collection<GrantedAuthority> authorities = extractAuthorities(jwt);

        // 3. 返回标准的 JwtAuthenticationToken
        return new JwtAuthenticationToken(jwt, authorities, username);
    }

    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        // 方式1：从 authorities 数组提取（你的情况）
        Object authoritiesObj = jwt.getClaims().get("authorities");
        if (authoritiesObj instanceof Collection) {
            return ((Collection<?>) authoritiesObj).stream()
                    .map(Object::toString)
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
        }

        // 方式2：从 scope/ scp 提取 SCOPE_ 权限
        return delegate.convert(jwt).getAuthorities();
    }
}