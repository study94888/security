package org.javaboy.authserver.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author shuxian
 * @date 2025-09-19
 * @description
 */

@Component
@Order(SecurityProperties.DEFAULT_FILTER_ORDER)
public class CookieTokenFilter extends OncePerRequestFilter {
    public CookieTokenFilter() {
        System.out.println("🔥 CookieTokenFilter 构造函数被执行！");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        System.out.println(">>>>>>>>>>>>>> COOKIE FILTER RUNNING <<<<<<<<<<<<<<");

        String token = null;

        // 1. 从 Cookie 中获取 AUTH-TOKEN
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("AUTH-TOKEN".equals(cookie.getName())) {
                    token = cookie.getValue();
                    break;
                }
            }
        }

        // 2. 如果找到 token，并且当前未认证
        if (token != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            try {
                // 3. 解析 JWT 或调用 /oauth/check_token 验证（根据你的 token 类型）
                // 这里以 JWT 为例：
                Claims claims = Jwts.parser()
                        .setSigningKey(AccessTokenConfig.SIGNING_KEY.getBytes())
                        .parseClaimsJws(token)
                        .getBody();

                String username = claims.getSubject();
                List<String> roles = (List<String>) claims.get("roles");

                Collection<GrantedAuthority> authorities = roles.stream()
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

                UsernamePasswordAuthenticationToken auth =
                        new UsernamePasswordAuthenticationToken(username, null, authorities);
                auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // 4. 设置到 SecurityContext
                SecurityContextHolder.getContext().setAuthentication(auth);
            } catch (Exception e) {
                // token 无效，忽略
                SecurityContextHolder.clearContext();
            }
        }

        filterChain.doFilter(request, response);
    }
}
