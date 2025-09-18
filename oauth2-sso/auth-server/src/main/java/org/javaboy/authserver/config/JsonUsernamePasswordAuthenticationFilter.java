package org.javaboy.authserver.config;


import org.codehaus.jackson.map.ObjectMapper;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

/**
 * @author shuxian
 * @date 2025-09-18
 * @description
 */

public class JsonUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {

        if (!"POST".equals(request.getMethod())) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }

        ObjectMapper mapper = new ObjectMapper();
        UsernamePasswordAuthenticationToken authRequest;
        Map<String, String> credentials = null;
        try {
            credentials = mapper.readValue(request.getInputStream(), Map.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        String username = credentials.get("username");
        String password = credentials.get("password");
        String state = credentials.get("state"); // ← 拿到 state
        // 将 state 存入 Session，供后续 SuccessHandler 使用
        request.getSession().setAttribute("OAUTH_STATE", state);

        authRequest = new UsernamePasswordAuthenticationToken(username, password);
        setDetails(request, authRequest);

        return this.getAuthenticationManager().authenticate(authRequest);

    }
}
