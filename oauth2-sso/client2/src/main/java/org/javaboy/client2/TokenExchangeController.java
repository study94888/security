package org.javaboy.client2;

import com.alibaba.fastjson.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.View;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;


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
    @Value("${security.oauth2.client_server.url}")
    private String CLIENT_SERVER;
    @Value("${security.oauth2.client.client-id}")
    private String CLIENT_ID;
    private static final String signingKey = "state-token-signing-key";
    public TokenExchangeController(View error) {
        this.error = error;
    }

    @Autowired
    @Qualifier("unsafeRestTemplate")
    private RestTemplate restTemplate; // 使用我们创建的“不安全”模板


    /**
     * 前端调用此接口获取带签名的 stateToken 和授权 URL
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
                AUTH_SERVER+"/oauth/authorize", CLIENT_ID, CLIENT_SERVER+"/oauth/callback", rawState
        );

        Map<String, String> result = new HashMap<>();
        result.put("authorizeUrl", authorizeUrl);
        return result;
    }

    /**
     * 授权服务器重定向到这里，后端验证 state 和 stateToken
     * @param request
     * @return
     */
    @GetMapping("/oauth/callback")
    public ResponseEntity<?> exchangeCode(CodeRequest request, HttpSession session, HttpServletResponse httpResponse) {
//        String expectedState = (String) session.getAttribute("oauth_state");
//        session.removeAttribute("oauth_state");
//        if (expectedState == null || !request.getState().equals(expectedState)) {
//            return ResponseEntity.badRequest().body("CSRF detected: invalid or missing state");
//        }

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("code", request.getCode());
        params.add("redirect_uri", "https://ax2.youku.com:1204/oauth/callback");
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
            ResponseEntity<Map> response = restTemplate
                    .postForEntity(tokenUri, entity, Map.class);
            JSONObject bodyObj = new JSONObject(response.getBody());
            String token = bodyObj.getString("access_token");
            // 设置 Cookie
            Cookie cookie = new Cookie("AUTH-TOKEN", token);
            cookie.setDomain("ax2.youku.com");
            cookie.setPath("/");
            cookie.setSecure(true);
            cookie.setHttpOnly(true); // JS 不能访问
            cookie.setMaxAge(3600); // 1小时
            httpResponse.addCookie(cookie);
            return             // 将 Cookie 添加到响应中
                    ResponseEntity.ok().body(response.getBody());// ✅ 把 JWT 返回前端
        } catch (HttpClientErrorException e) {
            // ✅ 打印详细错误
            System.err.println("Token request failed: " + e.getStatusCode());
            System.err.println("Response: " + e.getResponseBodyAsString());
            return null;
        }
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
