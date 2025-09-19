package org.javaboy.authserver;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.javaboy.authserver.config.AccessTokenConfig;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.View;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.*;
import java.util.stream.Collectors;


/**
 * @author shuxian
 * @date 2025-09-12
 * @description
 */
@RestController
public class TokenExchangeController {

    private final View error;
    @Value("${security.oauth2.client.access-token-uri}")
    private String tokenUri;
    @Value("${security.oauth2.auth_server.url}")
    private String AUTH_SERVER;
    @Value("${security.oauth2.client.user-authorization-uri}")
    private String AUTHORIZE_SERVER;
    @Value("${security.oauth2.client.client-id}")
    private String CLIENT_ID;
    private static final String signingKey = "state-token-signing-key";

    public TokenExchangeController(View error) {
        this.error = error;
    }


    /**
     * 前端调用此接口获取带签名的 stateToken 和授权 URL
     *
     * @param
     * @return
     */
    @GetMapping("/oauth/initiate")
    public Map<String, String> initiateAuth(HttpSession session) {
        String rawState = UUID.randomUUID().toString();
//        long expiresAt = System.currentTimeMillis() + 600_000; // 10分钟过期
        // 2. 使用 HMAC256 签名
//        Algorithm algorithm = Algorithm.HMAC256(signingKey);
//        String tokenString = JWT.create()
//                .withSubject(rawState)
//                .withExpiresAt(new Date(expiresAt))
//                .sign(algorithm);


        session.setAttribute("oauth_state", rawState);

        String authorizeUrl = String.format(
                "%s?client_id=%s&redirect_uri=%s&response_type=code&state=%s",
                AUTH_SERVER + "/oauth/authorize", CLIENT_ID, AUTH_SERVER + "/oauth/callback", rawState
        );


        Map<String, String> result = new HashMap<>();
        result.put("authorizeUrl", authorizeUrl);
        return result;
    }

    /**
     * 授权服务器重定向到这里，后端验证 state 和 stateToken
     *
     * @param request
     * @return
     */
//    @GetMapping("/oauth/callback")
    public ResponseEntity<?> exchangeCode(CodeRequest request, HttpSession session) {
        String expectedState = (String) session.getAttribute("oauth_state");
        session.removeAttribute("oauth_state");
        if (expectedState == null || !request.getState().equals(expectedState)) {
            return ResponseEntity.badRequest().body("CSRF detected: invalid or missing state");
        }

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("code", request.getCode());
        params.add("redirect_uri", "http://localhost:1201/oauth/callback");
        if (request.getCodeVerifier() != null) {
            params.add("code_verifier", request.getCodeVerifier()); // PKCE
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setBasicAuth("client1", "123");

        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(params, headers);
        System.out.println("URL: " + tokenUri);
        System.out.println("Headers: " + headers);
        System.out.println("Body: " + params);
        try {
            ResponseEntity<Map> response = new RestTemplate()
                    .postForEntity(tokenUri, entity, Map.class);
            return ResponseEntity.ok(response.getBody()); // ✅ 把 JWT 返回前端
        } catch (HttpClientErrorException e) {
            // ✅ 打印详细错误
            System.err.println("Token request failed: " + e.getStatusCode());
            System.err.println("Response: " + e.getResponseBodyAsString());
            return null;
        }
    }

    @GetMapping("/oauth/token/check")
    public ResponseEntity<?> checkCode(HttpServletRequest request, String clientId, String callbackUrl) {
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


                String redirectUri = AUTH_SERVER + "?" + "client_id=" + clientId + "&redirect_uri=" + callbackUrl + "&response_type=code&username=sang&password=123";
//                response.sendRedirect(redirectUri);

            } catch (Exception e) {
                // token 无效，忽略
                SecurityContextHolder.clearContext();
            }
        }
        return null;
    }


    static class CodeRequest {
        private String code;
        private String redirectUri;
        private String codeVerifier;
        private String state;

        public String getState() {
            return state;
        }

        public void setState(String state) {
            this.state = state;
        }

        public String getRedirectUri() {
            return redirectUri;
        }

        public void setRedirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
        }

        public String getCodeVerifier() {
            return codeVerifier;
        }

        public void setCodeVerifier(String codeVerifier) {
            this.codeVerifier = codeVerifier;
        }

        public String getCode() {
            return code;
        }

        public void setCode(String code) {
            this.code = code;
        }
// getter/setter
    }
}
