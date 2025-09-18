package org.javaboy.authserver.config;


import org.codehaus.jackson.map.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;


import java.io.InputStream;
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
    @Autowired
    private PermissiveAuthenticationProvider permissiveAuthenticationProvider;
    @Autowired
    private CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    @Autowired
    private RequestCache requestCache;
    @Autowired
    private OAuthRequestStore store;
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // 自定义入口点：返回 JSON 而不是跳转登录页
//    @Bean
//    public AuthenticationEntryPoint jsonAuthenticationEntryPoint() {
//        return new CustomAuthenticationEntryPoint();
//    }

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
                        customAuthenticationEntryPoint, // 使用 JSON 响应
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
                .cors() // 启用 CORS 配置（必须有 CorsFilter 才生效）
                .and()
                .csrf().disable()
                .addFilterAt(jsonLoginFilter(), UsernamePasswordAuthenticationFilter.class)
                // ✅ 显式启用 RequestCache
                .requestCache()
                .requestCache(requestCache) // 共享实例
                .and();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        config.setAllowCredentials(true); // 允许携带 Cookie
        config.addAllowedOrigin("https://pre.t.youku.com"); // ✅ 注意：生产环境建议精确指定

        config.addAllowedHeader("*");
        config.addAllowedMethod("*");
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return source;
    }


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(permissiveAuthenticationProvider);
//        auth.inMemoryAuthentication()
//                .withUser("sang")
//                .password(passwordEncoder().encode("123"))
//                .roles("admin");
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(UserDetailsService userDetailsService) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider() {
            @Override
            protected void additionalAuthenticationChecks(UserDetails userDetails,
                                                          UsernamePasswordAuthenticationToken authentication) {
                // 跳过密码检查
                String username = authentication.getName();
                if ("sang".equals(username)) {
                    return; // 不做任何检查
                }
                // 否则执行默认密码校验
                super.additionalAuthenticationChecks(userDetails, authentication);
            }
        };
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }


    /**
     * 显式声明 RequestCache Bean，供 CustomAuthenticationEntryPoint 注入
     */
    @Bean
    public RequestCache requestCache() {
        return new HttpSessionRequestCache();
    }


    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return (request, response, authentication) -> {
            SavedRequest savedRequest = requestCache().getRequest(request, response);
// 在 getRequest 前打印
            System.out.println("👉 CURRENT SESSION ID: " + request.getSession().getId());
            System.out.println("👉 SAVED REQUEST: " + savedRequest);
            System.out.println("👉 Request URI: " + request.getRequestURI());
            String state = (String) request.getSession().getAttribute("OAUTH_STATE");
            request.getSession().removeAttribute("OAUTH_STATE"); // 清理
            ObjectMapper mapper = new ObjectMapper();
            if (state != null) {
                String originalUrl = store.remove(state);
                if (originalUrl != null) {
                    response.sendRedirect(originalUrl); // 回到 authorize → 生成 code
                    return;
                }
            }


            String redirectUri = "https://localhost:1204/oauth/callback"; // 默认

            if (savedRequest != null) {
                // 获取原始请求的 URL 和参数
                redirectUri = savedRequest.getRedirectUrl(); // 完整 URL，含 redirect_uri 参数
            }
            // 登录成功，重定向回原始的 authorize 请求
//            String redirectUri = StringUtils.isEmpty( request.getParameter("redirect_uri"))? "https://www.baidu.com" :request.getParameter("redirect_uri");
//            String redirectUri = (String) request.getSession().getAttribute("saved_request_uri");
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

    @Bean
    public JsonUsernamePasswordAuthenticationFilter jsonLoginFilter() throws Exception {
        JsonUsernamePasswordAuthenticationFilter filter = new JsonUsernamePasswordAuthenticationFilter();
        filter.setAuthenticationManager(authenticationManagerBean());
        filter.setAuthenticationSuccessHandler(authenticationSuccessHandler());
        filter.setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler("/oauth/login?error"));
        filter.setRequiresAuthenticationRequestMatcher(
                new AntPathRequestMatcher("/oauth/login", "POST")
        );
        return filter;
    }
}
