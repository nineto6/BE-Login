package hello.Login.config;

import hello.Login.common.codes.AuthConstants;
import hello.Login.config.filter.CustomAuthenticationFilter;
import hello.Login.config.filter.JwtAuthorizationFilter;
import hello.Login.config.handler.*;
import hello.Login.config.redis.RedisRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.RequestCacheConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Spring Security 환경 설정을 구성하기 위한 클래스입니다.
 * 웹 서비스가 로드 될때 Spring Container 의해 관리가 되는 클래스이며 사용자에 대한 ‘인증’과 ‘인가’에 대한 구성을 Bean 메서드로 주입을 한다.
 */
@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfig {

    private final RedisRepository redisRepository;
    private final RedisTemplate<String, String> redisTemplate;

    /**
     * 1. 정적 자원(Resource)에 대해서 인증된 사용자가 정적 자원의 접근에 대해 ‘인가’에 대한 설정을 담당하는 메서드이다.
     * resources(css, js 등)의 경우 securityContext 등에 대한 조회가 불필요 하므로 disable 한다.
     * @return WebSecurityCustomizer
     */
    @Bean
    @Order(0)
    public SecurityFilterChain resources(HttpSecurity http) throws Exception {
        return http.requestMatchers(matchers -> matchers.antMatchers("/resources/**"))
                .authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll())
                .requestCache(RequestCacheConfigurer::disable)
                .securityContext(AbstractHttpConfigurer::disable)
                .sessionManagement(AbstractHttpConfigurer::disable)
                .build();
    }

    /**
     * 2. HTTP 에 대해서 '인증'과 '인가'를 담당하는 메서드이며 필터를 통해 인증 방식과 인증 절차에 대해서 등록하며 설정을 담당하는 메서드이다.
     * @param http HttpSecurity
     * @return SecurityFilterChain
     * @throws Exception exception
     */
    @Bean
    @Order(1)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        log.debug("[+] WebSecurityConfig Start !");

        http
                // [STEP1] 서버에 인증정보를 저장하지 않기에 csrf 를 사용하지 않는다.
                .csrf().disable()

                // [STEP2-1] 401, 403 Exception 핸들링 지정
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint())
                .accessDeniedHandler(jwtAccessDeniedHandler())
                .and()

                // [STEP2-2] JwtAuthorizationFilter 에서 사용자 인증 후 인가를 받은 권한에 대하여 접근 지정
                .authorizeHttpRequests()
                .antMatchers(
                        "/api/users/signup" // 회원가입
                        , "/api/users/duplicheck" // id 중복 체크
                        , "/api/users/reissue" // Jwt 토큰 재발급
                        , "/api/test/generateToken" // 토큰 발급 테스트
                ).permitAll() // 모든 권한 접근 가능 (Anonymous 포함)
                .antMatchers("/api/test/user").hasRole("USER") // USER 권한이 있을경우에만 접근 가능
                .antMatchers("/api/test/admin").hasRole("ADMIN") // ADMIN 권한이 있을경우에만 접근 가능
                .anyRequest().authenticated() // 나머지 URL 은 인증이 되어야지 접근 가능(anonymous 포함 X)
                .and()

                // [STEP3] Spring Security JWT Filter Load
                .addFilterBefore(jwtAuthorizationFilter(), BasicAuthenticationFilter.class)

                // [STEP4] Session 기반의 인증기반을 사용하지 않고 추후 JWT 를 이용하여 인증 예정
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                // [STEP5] form 기반의 로그인에 대해 비 활성화하며 커스텀으로 구성한 필터를 사용한다.
                .formLogin().disable()

                // [STEP6] Spring Security Custom Filter Load - Form '인증'에 대해서 사용
                .addFilterBefore(customAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)

                // CORS 설정
                .cors().configurationSource(corsConfigurationSource());
        // [STEP7] 최종 구성한 값을 사용함.
        return http.build();
    }

    /**
     * 3. authenticate 의 인증 메서드를 제공하는 매니져로'Provider'의 인터페이스를 의미합니다.
     * - 과정: CustomAuthenticationFilter → AuthenticationManager(interface) → CustomAuthenticationProvider(implements)
     * @return AuthenticationManager
     */
    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(customAuthenticationProvider());
    }

    /**
     * 4. '인증' 제공자로 사용자의 이름과 비밀번호가 요구됩니다.
     * - 과정: CustomAuthenticationFilter → AuthenticationManager(interface) → CustomAuthenticationProvider(implements)
     * @return CustomAuthenticationProvider
     */
    @Bean
    public CustomAuthenticationProvider customAuthenticationProvider() {
        return new CustomAuthenticationProvider(bCryptPasswordEncoder());
    }

    /**
     * 5. 비밀번호를 암호화하기 위한 BCrypt 인코딩을 통하여 비밀번호에 대한 암호화를 수행합니다.
     * @return BCryptPasswordEncoder
     */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 6. 커스텀을 수행한 '인증' 필터로 접근 URL, 데이터 전달방식(form) 등 인증 과정 및 인증 후 처리에 대한 설정을 구성하는 메서드입니다.
     * @return CustomAuthenticationFilter
     */
    @Bean
    public CustomAuthenticationFilter customAuthenticationFilter() {
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(authenticationManager());
        customAuthenticationFilter.setFilterProcessesUrl("/api/users/login"); // 접근 URL
        customAuthenticationFilter.setAuthenticationSuccessHandler(customLoginSuccessHandler()); // '인증' 성공 시 해당 핸들러로 처리를 전가한다.
        customAuthenticationFilter.setAuthenticationFailureHandler(customLoginFailureHandler()); // '인증' 실패 시 해당 핸들러로 처리를 전가한다.
        customAuthenticationFilter.afterPropertiesSet();
        return customAuthenticationFilter;
    }

    /**
     * 7. Spring Security 기반의 사용자의 정보가 맞을 경우 수행이 되며 결과값을 리턴해주는 Handler
     * @return CustomLoginSuccessHandler
     */
    @Bean
    public CustomAuthSuccessHandler customLoginSuccessHandler() {
        return new CustomAuthSuccessHandler(redisRepository);
    }

    /**
     * 8. Spring Security 기반의 사용자의 정보가 맞지 않을 경우 수행이 되며 결과값을 리턴해주는 Handler
     * @return CustomAuthFailureHandler
     */
    @Bean
    public CustomAuthFailureHandler customLoginFailureHandler() {
        return new CustomAuthFailureHandler();
    }

    /**
     * 9. CORS 설정
     * @return UrlBasedCorsConfigurationSource
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.addAllowedOrigin("https://localhost:3000/");
        configuration.addAllowedHeader("*");
        configuration.addAllowedMethod("*");
        configuration.setAllowCredentials(true);
        configuration.addExposedHeader(AuthConstants.AUTH_HEADER);
        configuration.addExposedHeader(AuthConstants.AUTH_ACCESS);
        configuration.addExposedHeader(AuthConstants.AUTH_REFRESH);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    /**
     * 10. JWT 토큰을 통하여서 사용자를 인증합니다.
     * @return JwtAuthorizationFilter
     */
    @Bean
    public JwtAuthorizationFilter jwtAuthorizationFilter() {
        return new JwtAuthorizationFilter(redisTemplate);
    }

    /**
     * 11. 401 Unauthorized Exception 처리
     * @return JwtAuthenticationEntryPoint
     */
    @Bean
    public AuthenticationEntryPoint jwtAuthenticationEntryPoint() {
        return new JwtAuthenticationEntryPoint();
    }

    /**
     * 12. 403 Forbidden Exception 처리
     * @return JwtAccessDeniedHandler
     */
    @Bean
    public AccessDeniedHandler jwtAccessDeniedHandler() {
        return new JwtAccessDeniedHandler();
    }

}
