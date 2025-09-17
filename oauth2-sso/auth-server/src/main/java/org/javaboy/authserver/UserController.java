package org.javaboy.authserver;

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

import javax.servlet.http.HttpSession;
import java.security.Principal;
import java.util.Map;

/**
 * @作者 江南一点雨
 * @微信公众号 江南一点雨
 * @网站 http://www.itboyhub.com
 * @国际站 http://www.javaboy.org
 * @微信 a_java_boy
 * @GitHub https://github.com/lenve
 * @Gitee https://gitee.com/lenve
 */
@RestController
public class UserController {


    private static String tokenUri ="http://localhost:1201/oauth/token" ;
    @GetMapping("/user")
    public Principal getCurrentUser(Principal principal) {
        return principal;
    }

    @GetMapping("/hello")
    public String hello() {
        return "hello";
    }



    @GetMapping("/oauth/callback")
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
        headers.setBasicAuth("platform", "123");

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
