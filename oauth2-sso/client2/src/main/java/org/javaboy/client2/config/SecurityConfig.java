package org.javaboy.client2.config;


import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;


import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;

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
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private static final String SIGNING_KEY = "my-super-long-and-secure-signing-key!";
    @Bean
    public AuthenticationEntryPoint jsonAuthenticationEntryPoint() {
        return new CustomAuthenticationEntryPoint();
    }
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/oauth/callback").permitAll()
                .antMatchers("/oauth/initiate").permitAll()
                .antMatchers("/hello").authenticated()       // 需要登录才能访问
                .anyRequest().permitAll()
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                // JWT 资源服务器，会直接验证 JWT token，而不会将请求转发到授权服务器进行认证。/hello
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt ->{
                            jwt.decoder(jwtDecoder());
                            jwt.jwtAuthenticationConverter(new CustomJwtAuthenticationConverter());
                                } )                        // 使用自定义 decoder 验证签名
                        )
                .exceptionHandling()
                .authenticationEntryPoint( jsonAuthenticationEntryPoint())
                .and()
                .cors()
                .and()
                // 前后端分离不需要 CSRF（如果是 Cookie 登录则需要）
                .csrf().disable();

        // 不再使用 .oauth2Login() 或 @EnableOAuth2Sso
        // 让我们自己控制流程
//        http.authorizeRequests().anyRequest().authenticated().and().csrf().disable();
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

    @Bean
    public JwtDecoder jwtDecoder() {
        // 使用 HMAC-SHA256 对称加密
        System.out.println("✅ 正在创建 JwtDecoder，密钥: " + SIGNING_KEY);
        System.out.println("密钥长度: " + SIGNING_KEY.getBytes(StandardCharsets.UTF_8).length + " 字节");
        System.out.println("Key bytes: " + Arrays.toString(SIGNING_KEY.getBytes(StandardCharsets.UTF_8)));
        System.out.println("Key length: " + SIGNING_KEY.getBytes(StandardCharsets.UTF_8).length);

        byte[] keyBytes = SIGNING_KEY.getBytes(StandardCharsets.UTF_8);
        SecretKeySpec hmacKey = new SecretKeySpec(keyBytes, "HmacSHA256");
        if (keyBytes.length < 32) {
            throw new IllegalArgumentException("Signing key must be at least 256 bits");
        }
        return NimbusJwtDecoder.withSecretKey(hmacKey).build();
    }

    @Bean("unsafeRestTemplate")
    public RestTemplate unsafeRestTemplate() {
        try {
            // 创建信任所有证书的 TrustManager
            TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
                        public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) { }
                        public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) { }
                    }
            };

            // 创建 SSLContext
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());

            // 创建 HttpClient
            CloseableHttpClient httpClient = HttpClients.custom()
                    .setSSLContext(sslContext)
                    .setSSLHostnameVerifier((hostname, session) -> true) // 忽略域名验证
                    .build();

            // 创建 factory
            HttpComponentsClientHttpRequestFactory factory =
                    new HttpComponentsClientHttpRequestFactory(httpClient);

            return new RestTemplate(factory);

        } catch (Exception e) {
            throw new RuntimeException("Failed to create unsafe RestTemplate", e);
        }
    }

}