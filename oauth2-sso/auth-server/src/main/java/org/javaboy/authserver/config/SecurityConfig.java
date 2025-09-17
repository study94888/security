package org.javaboy.authserver.config;

import org.codehaus.jackson.map.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.HashMap;
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
@Configuration
@Order(1)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    // 自定义入口点：返回 JSON 而不是跳转登录页
    @Bean
    public AuthenticationEntryPoint jsonAuthenticationEntryPoint() {
        return new CustomAuthenticationEntryPoint();
    }
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/login.html", "/css/**", "/js/**", "/images/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.requestMatchers()
                .antMatchers("/login")
                .antMatchers("/oauth/authorize")
                .antMatchers("/oauth/token")
                .antMatchers("/oauth/login")
                .and()
                .authorizeRequests().anyRequest().authenticated()
                .and()
                // 自定义未认证处理
                .exceptionHandling()
                .defaultAuthenticationEntryPointFor(
                        new CustomAuthenticationEntryPoint(), // 使用 JSON 响应
                        new AntPathRequestMatcher("/oauth/authorize") // 只对 /oauth/authorize 生效
                )
                .and()
                .formLogin()
                .loginPage("/oauth/authorize") // 登录页仍是 authorize（触发EntryPoint）
                .loginProcessingUrl("/oauth/login") // 自定义登录提交地址
                .successHandler(authenticationSuccessHandler()) // 登录成功处理器
                .failureHandler(authenticationFailureHandler()) // 登录失败处理器
                .permitAll()
                .and()
                .csrf().disable();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("sang")
                .password(passwordEncoder().encode("123"))
                .roles("admin");
    }

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return (request, response, authentication) -> {
            // 登录成功，重定向回原始的 authorize 请求
            String redirectUri = (String) request.getSession().getAttribute("saved_request_uri");
            if (redirectUri == null) {
                redirectUri = "/";
            }
            response.sendRedirect(redirectUri);
        };
    }
    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        return (request, response, exception) -> {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setContentType("application/json;charset=UTF-8");
            Map<String, Object> result = new HashMap<>();
            result.put("success", false);
            result.put("code", 1001);
            result.put("msg", "用户名或密码错误");
            result.put("data", null);
            ObjectMapper mapper = new ObjectMapper();
            response.getWriter().write(mapper.writeValueAsString(result));
        };
    }


}
