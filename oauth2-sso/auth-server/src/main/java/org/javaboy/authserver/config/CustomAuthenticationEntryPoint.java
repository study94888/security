package org.javaboy.authserver.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * @author shuxian
 * @date 2025-09-12
 * @description
 */
@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

        private ObjectMapper mapper = new ObjectMapper();

        @Override
        public void commence(HttpServletRequest request, HttpServletResponse response,
                             AuthenticationException authException) throws ServletException {
//            Map<String, Object> map = new HashMap<String, Object>();
//            Throwable cause = authException.getCause();
//            if(cause instanceof InvalidTokenException) {
//                map.put("code", 401);//401
//                map.put("msg", "无效的token");
//            }else{
//                map.put("code", "UNAUTHORIZED");//401
//                map.put("msg", "访问此资源需要完全的身份验证");
//            }
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setContentType("application/json;charset=UTF-8");

            Map<String, Object> result = new HashMap<>();
            result.put("success", false);
            result.put("code", 1001); // 自定义错误码：未登录
            result.put("msg", "用户未登录，请前往授权");
            result.put("data", null);
            result.put("path", request.getRequestURI());
            result.put("timestamp", System.currentTimeMillis());
//            map.put("data", authException.getMessage());
//            map.put("success", false);
//            map.put("path", request.getServletPath());
//            map.put("timestamp", String.valueOf(new Date().getTime()));
            response.setContentType("application/json;charset=UTF-8");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            try {
                mapper.writeValue(response.getOutputStream(), result);
            } catch (Exception e) {
                throw new ServletException();
            }
        }
    }