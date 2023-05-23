# 🛠️NINETO6 사이드프로젝트 만들기

## 시작하기 전에...

ErrorCode, Security, JWT 등을 참고한 사이트 출처 [Contributor9 블로그](https://adjh54.tistory.com)
<br/>
<p>
<img src="https://img.shields.io/badge/Java-007396.svg?&style=for-the-badge&logo=Java&logoColor=white"/>
<img src="https://img.shields.io/badge/Spring%20Boot-6DB33F.svg?&style=for-the-badge&logo=SpringBoot&logoColor=white"/>
<img src="https://img.shields.io/badge/Spring-6DB33F.svg?&style=for-the-badge&logo=Spring&logoColor=white"/>
<img src="https://img.shields.io/badge/MyBatis-000000.svg?&style=for-the-badge&logoColor=white">
<p/>

- 현재 `Front-End` 와 `Back-end` 는 다른 환경에서 개발하고 있음
- Project : Gradle
- SpringBoot 버전 : 2.7.11
- Java 버전 : 11
- Dependencies
   - Spring Web:1.6.12
   - Spring Security:5.7.8
   - Mybatis:3.5.11
   - Lombok:1.2.12
   - H2 Database:2.1.214
<br/>
<hr/>

###### 20230501
> ## application.properties 작성
- Datasource url, username, password
```text
# h2 database
spring.datasource.url=jdbc:h2:tcp://localhost/~/test
spring.datasource.username=sa
spring.datasource.password=
```
- Spring, Mybatis 로그 및 Mybatis 설정
```test
#Spring Log
logging.level.hello.Login=trace

#MyBatis Log
logging.level.hello.Login.mapper.mybatis=trace

#관계형 데이터베이스(snake_case)에서 자바 객체(camelCase)로 언더스코어 표기법을 카멜로 자동 변경해준다.
mybatis.configuration.map-underscore-to-camel-case=true
```

> ## User 스키마 작성
```SQL
create table tb_user(
   user_sq        int auto_increment primary key,
   user_id        varchar(20) not null,
   user_pw        varchar(20) not null,
   user_nm        varchar(20) not null,
   user_st        varchar(1) not null
);
```

> ## UserDto 작성
```Java
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class UserDto {

    // 사용자 시퀀스
    private int userSq;

    // 사용자 아이디
    private String userId;

    // 사용자 패스워드
    private String userPw;

    // 사용자 이름
    private String userNm;

    // 사용자 상태
    private String userSt;

    @Builder
    UserDto(int userSq, String userId, String userPw, String userNm, String userSt) {
        this.userSq = userSq;
        this.userId = userId;
        this.userPw = userPw;
        this.userNm = userNm;
        this.userSt = userSt;
    }
}
```

> ## UserMapper 작성
```Java
@Mapper
public interface UserMapper {
    Optional<UserDto> login(UserDto userDto);
}
```

> ## UserMapper.xml 작성
- MyBatis #{} 바인딩을 사용하여 SQL Injection 방지
   - #{} : 파라미터가 String 형태로 들어와 자동적으로 파라미터 형태가 된다.
      예를들어, #{user_id}의 user_id의 값이 abc 라면 쿼리문에는 USER_ID = 'abc'의 형태가 된다.
      SQL Injection을 예방할 수 있어 보안측면에서 유리하다.

   - ${} : 파라미터가 바로 출력된다.
      해당 컬럼의 자료형에 맞추어 파라미터의 자료형이 변경된다.
      SQL Injection을 예방할 수 없어 보안 측면에서 불리하다. 그러므로, 사용자의 입력을 전달할 때는 사용하지 않는 편이 좋다.
      테이블이나 컬럼명을 파라미터로 전달하고 싶을 때 사용한다. #{} 은 자동으로 ''가 붙어서 이 경우에는 사용할 수 없다.
```Xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">

<mapper namespace="hello.Login.mapper.UserMapper">
    <!-- 로그인 -->
    <select id="login" resultType="hello.Login.model.UserDto">
        SELECT t1.*
        FROM tb_user t1
        WHERE user_id = #{userId}
    </select>
</mapper>
```
> ## UserService 인터페이스 작성
```Java
public interface UserService {
    Optional<UserDto> login(UserDto userDto);
}
```

> ## UserServiceImpl 작성
```Java
@Service
@Slf4j
@RequiredArgsConstructor
public class UserServiceImpl implements UserService{

    private final UserMapper userMapper;

    /**
     * 로그인 구현체
     * @param userDto UserDto
     * @return Optional<UserDto>
     */
    @Override
    public Optional<UserDto> login(UserDto userDto) {
        return userMapper.login(userDto);
    }
}
```

> ## UserDetailsDto 작성
```Java
@Slf4j
@Getter
@AllArgsConstructor
public class UserDetailsDto implements UserDetails {

    @Delegate
    /* @Delegate : UserDto 의 메서드가 위임되어서 UserDetailsDto 에서 바로 호출이 가능 */
    private UserDto userDto;
    private Collection<? extends GrantedAuthority> authorities;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return userDto.getUserPw();
    }

    @Override
    public String getUsername() {
        return userDto.getUserNm();
    }

    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    @Override
    public boolean isEnabled() {
        return false;
    }
}
```

> ## UserDetailsServiceImpl 작성
```Java
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserService userService;

    public UserDetailsServiceImpl(UserService us) {
        this.userService = us;
    }
    @Override
    public UserDetails loadUserByUsername(String userId) throws UsernameNotFoundException {
        UserDto userDto = UserDto
                .builder()
                .userId(userId)
                .build();

        // 사용자 정보가 존재하지 않는 경우 예외 처리
        if(userId == null || userId.equals("")) {
            return userService.login(userDto)
                    .map(u -> new UserDetailsDto(u, Collections.singleton(new SimpleGrantedAuthority(u.getUserId()))))
                    .orElseThrow(() -> new AuthenticationServiceException(userId));
        }

        // 비밀번호가 맞지 않는 경우 예외 처리
        else {
            return userService.login(userDto)
                    .map(u -> new UserDetailsDto(u, Collections.singleton(new SimpleGrantedAuthority(u.getUserId()))))
                    .orElseThrow(() -> new BadCredentialsException(userId));
        }
    }
}
```

> ## Dependencies 추가
- implementation 'com.googlecode.json-simple:json-simple:1.1.1' // simple-json 추가

> ## CustomAuthenticationFilter 작성
- 아이디와 비밀번호 기반의 데이터를 Form 데이터로 전송을 받아 '인증'을 담당하는 필터
```Java
@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    public CustomAuthenticationFilter(AuthenticationManager authenticationManager) {
        super.setAuthenticationManager(authenticationManager);
    }

    /**
     * 지정된 URL 로 form 전송을 하였을 경우 파라미터 정보를 가져온다.
     *
     * @param request  from which to extract parameters and perform the authentication
     * @param response the response, which may be needed if the implementation has to do a
     *                 redirect as part of a multi-stage authentication process (such as OpenID).
     * @return Authentication {}
     * @throws AuthenticationException {}
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        UsernamePasswordAuthenticationToken authRequest;
        try {
            authRequest = getAuthRequest(request);
            setDetails(request, authRequest);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return this.getAuthenticationManager().authenticate(authRequest);
    }

    /**
     * Request 로 받은 ID와 패스워드 기반으로 토큰을 발급한다.
     *
     * @param request HttpServletRequest
     * @return UsernamePasswordAuthenticationToken
     * @throws Exception e
     */
    private UsernamePasswordAuthenticationToken getAuthRequest(HttpServletRequest request) throws Exception {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            objectMapper.configure(JsonParser.Feature.AUTO_CLOSE_SOURCE, true);
            UserDto user = objectMapper.readValue(request.getInputStream(), UserDto.class);
            log.debug("1.CustomAuthenticationFilter :: userId:{} userPw:{}", user.getUserId(), user.getUserPw());

            // ID 와 패스워드를 기반으로 토큰 발급
            return new UsernamePasswordAuthenticationToken(user.getUserId(), user.getUserPw());
        } catch(UsernameNotFoundException ae) {
            throw new UsernameNotFoundException(ae.getMessage());
        } catch (Exception e) {
            throw new Exception(e.getMessage(), e.getCause());
        }
    }

}
```

> ## CustomAuthSuccessHandler 작성
- 사용자의 '인증'에 대해 성공하였을 경우 수행되는 Handler로 성공에 대한 사용자에게 반환값을 구성하여 전달
```Java
@Slf4j
@Configuration
public class CustomAuthSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws ServletException, IOException {
        log.debug("3. CustomLoginSuccessHandler");

        // [STEP1] 사용자와 관련된 정보를 모두 조회합니다.
        UserDto userDto = ((UserDetailsDto) authentication.getPrincipal()).getUserDto();

        // [STEP2] 조회한 데이터를 JSONObject 형태로 파싱을 수행합니다.
        JSONObject userVoObj = (JSONObject)JSONValue.parse(new ObjectMapper().writeValueAsString(userDto));

        HashMap<String, Object> responseMap = new HashMap<>();

        JSONObject jsonObject;
        // [STEP3-1] 사용자의 상태가 '휴먼 상태' 인 경우 응답 값으로 전달 할 데이터
        if(userDto.getUserSt().equals("D")) {
            responseMap.put("userInfo", userVoObj);
            responseMap.put("resultCode", 9001);
            responseMap.put("token", null);
            responseMap.put("failMsg", "휴먼 계정입니다.");
            jsonObject = new JSONObject(responseMap);
        }

        // [STEP3-2] 사용자의 상태가 '휴먼 상태'가 아닌 경우 응답 값으로 전달할 데이터
        else {
            // 1. 일반 계정일 경우 데이터 세팅
            responseMap.put("userInfo", userVoObj);
            responseMap.put("resultCode", 200);
            responseMap.put("failMsg", null);
            jsonObject = new JSONObject(responseMap);

            // TODO: 추후 JWT 발급에 사용할 예정
            String token = TokenUtils.generateJwtToken(userDto);
            response.addHeader(AuthConstants.AUTH_HEADER, AuthConstants.TOKEN_TYPE + " " + token);
        }

        // [STEP4] 구성한 응답 값을 전달합니다.
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json");
        PrintWriter printWriter = response.getWriter();
        printWriter.print(jsonObject); // 최정 저장된 '사용자 정보', '사이트 정보' Front 전달
        printWriter.flush();
        printWriter.close();
    }
}
```

> ## CustomAuthFailureHandler 작성
- 사용자의 '인증'에 대해 실패하였을 경우 수행되는 Handler로 실패에 대한 사용자에게 반환값을 구성하여 전달
```Java
@Slf4j
@Configuration
public class CustomAuthFailureHandler implements AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        // [STEP1] 클라이언트로 전달 할 응답 값을 구성합니다.
        JSONObject jsonObject = new JSONObject();
        String failMsg = "";

        // [STEP2] 발생한 Exception 에 대해서 확인합니다.
        if(exception instanceof AuthenticationServiceException) {
            failMsg = "로그인 정보가 일치하지 않습니다.";
        } else if(exception instanceof BadCredentialsException) {
            failMsg = "로그인 정보가 일치하지 않습니다.";
        } else if(exception instanceof LockedException) {
            failMsg = "로그인 정보가 일치하지 않습니다.";
        } else if(exception instanceof AccountExpiredException) {
            failMsg = "로그인 정보가 일치하지 않습니다.";
        } else if(exception instanceof CredentialsExpiredException) {
            failMsg = "로그인 정보가 일치하지 않습니다.";
        }

        // [STEP3] 응답 값을 구성하고 전달합니다.
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json");
        PrintWriter printWriter = response.getWriter();

        log.debug("failMsg: {}", failMsg);

        HashMap<String, Object> resultMap = new HashMap<>();
        resultMap.put("userInfo", null);
        resultMap.put("resultCode", 9999);
        resultMap.put("failMsg", failMsg);
        jsonObject = new JSONObject(resultMap);

        printWriter.print(jsonObject);
        printWriter.flush();
        printWriter.close();
    }
}
```

> ## CustomAuthenticationProvider 작성
- 전달받은 사용자의 아이디와 비밀번호를 기반으로 비즈니스 로직을 처리하여 사용자의 '인증'에 대해서 검증을 수행하는 클래스
- CustomAuthenticationFilter로 부터 생성한 토큰을 통하여 'UserDetailsService'를 통해 데이터베이스 내에서 정보를 조회
```Java
@Slf4j
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Resource
    private UserDetailsService userDetailsService;

    @NonNull
    private BCryptPasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        log.debug("2.CustomAuthenticationProvider");

        UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) authentication;

        // 'AuthenticationFilter' 에서 생성된 토큰으로부터 아이디와 비밀번호를 조회
        String userId = token.getName();
        String userPw = (String) token.getCredentials();

        // Spring Security - UserDetailsService 를 통해 DB 에서 아이디로 사용자 조회
        UserDetailsDto userDetailsDto = (UserDetailsDto) userDetailsService.loadUserByUsername(userId);

        if (!(userDetailsDto.getUserPw().equalsIgnoreCase(userPw))) {
            throw new BadCredentialsException(userDetailsDto.getUserNm() + " Invalid password");
        }

        return new UsernamePasswordAuthenticationToken(userDetailsDto, userPw, userDetailsDto.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
```

> ## WebSecurityConfig 작성
- Spring Security 환경 설정을 구성하기 위한 클래스
- 웹 서비스가 로드 될때 Spring Container에 의해 관리가 되는 클래스이며 사용자에 대한 '인증'과 '인가'에 대한 구성을 Bean 메서드로 주입을 한다.
```Java
@Slf4j
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    /**
     * 1. 정적 자원(Resource)에 대해서 인증된 사용자가 정적 자원의 접근에 대해 ‘인가’에 대한 설정을 담당하는 메서드이다.
     * @return WebSecurityCustomizer
     */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        // 정적 자원에 대해서 Security 를 적용하지 않음으로 설정
        return web -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    /**
     * 2. HTTP 에 대해서 '인증'과 '인가'를 담당하는 메서드이며 필터를 통해 인증 방식과 인증 절차에 대해서 등록하며 설정을 담당하는 메서드이다.
     * @param http HttpSecurity
     * @return SecurityFilterChain
     * @throws Exception exception
     */
     @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        log.debug("[+] WebSecurityConfig Start !");

        http
                // [STEP1] 서버에 인증정보를 저장하지 않기에 csrf 를 사용하지 않는다.
                .csrf().disable()

                // [STEP2] 토큰을 활용하는 경우 모든 요청에 대해 '인가'에 대해서 적용
                .authorizeHttpRequests(authz -> authz.anyRequest().permitAll())

                // [STEP3] Spring Security JWT Filter Load
                //.addFilterBefore(jwtAuthorizationFilter(), BasicAuthenticationFilter.class) // JWT 관련 로직(주석 처리)

                // [STEP4] Session 기반의 인증기반을 사용하지 않고 추후 JWT 를 이용하여 인증 예정
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                // [STEP5] form 기반의 로그인에 대해 비 활성화하며 커스텀으로 구성한 필터를 사용한다.
                .formLogin().disable()

                // [STEP6] Spring Security Custom Filter Load - Form '인증'에 대해서 사용
                .addFilterBefore(customAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

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
        customAuthenticationFilter.setFilterProcessesUrl("/api/user/login"); // 접근 URL
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
        return new CustomAuthSuccessHandler();
    }

    /**
     * 8. Spring Security 기반의 사용자의 정보가 맞지 않을 경우 수행이 되며 결과값을 리턴해주는 Handler
     * @return CustomAuthFailureHandler
     */
    @Bean
    public CustomAuthFailureHandler customLoginFailureHandler() {
        return new CustomAuthFailureHandler();
    }
}
```

> ## 문제 발생
- .../api/user/login URL에 Front에서 Back 서버로 요청 및 응답을 확인을 하였으나 HTTP 응답시 CORS 오류 확인
<br/>
<hr/>

##### 20230502

> ## CORS 문제 해결 및 설정 코드 작성
- 프론트와 요청을 주고받을 수 있게 WebSecurityConfig에 코드 추가 및 Bean 등록
```Java
@Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        log.debug("[+] WebSecurityConfig Start !");

        http
                // [STEP1] 서버에 인증정보를 저장하지 않기에 csrf 를 사용하지 않는다.
                .csrf().disable()

                // [STEP2] 토큰을 활용하는 경우 모든 요청에 대해 '인가'에 대해서 적용
                .authorizeHttpRequests(authz -> authz.anyRequest().permitAll())

                // [STEP3] Spring Security JWT Filter Load
                //.addFilterBefore(jwtAuthorizationFilter(), BasicAuthenticationFilter.class)

                // [STEP4] Session 기반의 인증기반을 사용하지 않고 추후 JWT 를 이용하여 인증 예정
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                // [STEP5] form 기반의 로그인에 대해 비 활성화하며 커스텀으로 구성한 필터를 사용한다.
                .formLogin().disable()

                // [STEP6] Spring Security Custom Filter Load - Form '인증'에 대해서 사용
                .addFilterBefore(customAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

                // CORS 설정
                .cors().configurationSource(corsConfigurationSource()); // ** 추가 **
                // [STEP7] 최종 구성한 값을 사용함.
        return http.build();
    }
/**
 * 9. CORS 설정
 * @return
 */
@Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.addAllowedOrigin("http://localhost:3000");
        configuration.addAllowedHeader("*");
        configuration.addAllowedMethod("*");
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
```
- .../api/user/login URL에 Front에서 Back 서버로 요청 및 응답을 확인하여 200 정상 응답코드 확인
- Back 서버에서의 로그 확인 이미지
<img src="https://github.com/nineto6/BE-Login/blob/main/md_resource/be_resource_01.png">
<br/>
<hr/>

##### 20230503
> ## Dependencies 추가
- implementation 'org.springdoc:springdoc-openapi-ui:1.6.12' // Swagger 추가
- implementation 'org.glassfish.jaxb:jaxb-runtime:2.3.2' // DataTypeConverter 추가

> ## ErrorCode
- API 통신에 대한 '에러 코드'를 Enum 형태로 관리를 한다.
   - Global Error CodeList : 전역으로 발생하는 에러코드를 관리한다.
   - custom Error CodeList : 업무 페이지에서 발생하는 에러코드를 관리한다.
   - Error Code Constructor : 에러코드를 직접적으로 사용하기 위한 생성자를 구성한다.
```Java
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public enum ErrorCode {
    BUSINESS_EXCEPTION_ERROR(200, "B999", "Business Exception Error"),

    /**
     * *********************************** custom Error CodeList ********************************************
     */
    // Transaction Insert Error
    INSERT_ERROR(200, "9999", "Insert Transaction Error Exception"),

    // Transaction Update Error
    UPDATE_ERROR(200, "9999", "Update Transaction Error Exception"),

    // Transaction Delete Error
    DELETE_ERROR(200, "9999", "Delete Transaction Error Exception"),

    ; // End

    /**
     * *********************************** Error Code Constructor ********************************************
     */
    // 에러 코드의 '코드 상태'을 반환한다.
    private int status;

    // 에러 코드의 '코드간 구분 값'을 반환한다.
    private String divisionCode;

    // 에러코드의 '코드 메시지'을 반환한다.
    private String message;

    // 생성자 구성
    ErrorCode(final int status, final String divisionCode, final String message) {
        this.status = status;
        this.divisionCode = divisionCode;
        this.message = message;
    }
}
```

> ## SuccessCode
- API 통신에 대한 '에러 코드'를 Enum 형태로 관리를 한다.
   - Success CodeList : 성공 코드를 관리한다.
   - Success Code Constructor : 성공 코드를 사용하기 위한 생성자를 구성한다.
```Java
@Getter
public enum SuccessCode {

    /**
     * ******************************* Success CodeList ***************************************
     */
    // 조회 성공 코드 (HTTP Response: 200 OK)
    SELECT_SUCCESS(200, "200", "SELECT SUCCESS"),
    // 삭제 성공 코드 (HTTP Response: 200 OK)
    DELETE_SUCCESS(200, "200", "DELETE SUCCESS"),
    // 삽입 성공 코드 (HTTP Response: 201 Created)
    INSERT_SUCCESS(201, "201", "INSERT SUCCESS"),
    // 수정 성공 코드 (HTTP Response: 201 Created)
    UPDATE_SUCCESS(204, "204", "UPDATE SUCCESS"),

    ; // End

    /**
     * ******************************* Success Code Constructor ***************************************
     */
    // 성공 코드의 '코드 상태'를 반환한다.
    private final int status;

    // 성공 코드의 '코드 값'을 반환한다.
    private final String code;

    // 성공 코드의 '코드 메시지'를 반환한다.s
    private final String message;

    // 생성자 구성
    SuccessCode(final int status, final String code, final String message) {
        this.status = status;
        this.code = code;
        this.message = message;
    }
}
```

> ## BusinessExceptionHandler
- 예외 처리 관리를 하기위한 Business Layer인 ExceptionHandler
- ExceptionHandler의 장점
   1. 예외 처리를 위한 일관된 방법을 제공한다.
   2. 예외가 발생할 경우 처리하기 위한 구조를 제공하므로 코드의 가독성을 높일 수 있다.
   3. 예외 처리를 통해 프로그램의 안전성과 신뢰성을 높일 수 있다.
```Java
public class BusinessExceptionHandler extends RuntimeException {

    @Getter
    private final ErrorCode errorCode;

    @Builder
    public BusinessExceptionHandler(String message, ErrorCode errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    @Builder
    public BusinessExceptionHandler(ErrorCode errorCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
    }
}
```

> ## ApiResponse
- 요청 API 또는 Error 발생 유무에 따라 Response의 구조가 매번 다르게 리턴되는 것을 개선하기 위해 
- ApiResponse를 만들어서 모든 API 요청에 대해 해당 타입으로 한 번 감싸서 리턴하도록 변경
```Java
@Getter
public class ApiResponse {
    String result;
    int resultCode;
    String resultMsg;

    @Builder
    public ApiResponse(String result, int resultCode, String resultMsg) {
        this.result = result;
        this.resultCode = resultCode;
        this.resultMsg = resultMsg;
    }
}
```
<br/>
<hr/>

##### 20230504
> ## Dependencies 추가
- implementation 'io.jsonwebtoken:jjwt:0.9.1' // jwt 

> ## AuthConstants 추가
- JWT 관련된 상수로 사용 되는 파일
```Java
public final class AuthConstants {
    public static final String AUTH_HEADER = "Authorization";
    public static final String TOKEN_TYPE = "BEARER";
}
```

> ## TokenUtils 추가
> - JWT 관련된 토큰 Util
```Java
@Slf4j
public class TokenUtils {

    // @Value(value = "${custom.jwt-secret-key}")
    private static final String jwtSecretKey = "exampleSecretKey";

    /**
     * 사용자 정보를 기반으로 토큰을 생성하여 반환 해주는 메서드
     * @param userDto UserDto : 사용자 정보
     * @return String : 토큰
     */
    public static String generateJwtToken(UserDto userDto) {
        // 사용자 시퀀스를 기준으로 JWT 토큰을 발급하여 반환해줍니다.
        JwtBuilder builder = Jwts.builder()
                .setHeader(createHeader())                             // Header 구성
                .setClaims(createClaims(userDto))                      // Payload - Claims 구성
                .setSubject(String.valueOf(userDto.getUserSq()))       // Payload - Subject 구성
                .signWith(SignatureAlgorithm.HS256, createSignature()) // Signature 구성
                .setExpiration(createExpiredDate());                   // Expired Date 구성
        return builder.compact();
    }

    /**
     * 토큰을 기반으로 사용자 정보를 반환 해주는 메서드
     * @param token String : 토큰
     * @return String : 사용자 정보
     */
    public static String parseTokenToUserInfo(String token) {
        return Jwts.parser()
                .setSigningKey(jwtSecretKey)
                .parseClaimsJwt(token)
                .getBody()
                .getSubject();
    }

    /**
     * 유효한 토큰인지 확인 해주는 메서드
     * @param token String  : 토큰
     * @return      boolean : 유효한지 여부 반환
     */
    public static boolean isValidToken(String token) {
        try {
            Claims claims = getClaimsFormToken(token);

            log.info("expireTime : {}", claims.getExpiration());
            log.info("userId : {}", claims.get("userId"));
            log.info("userNm : {}", claims.get("userNm"));

            return true;
        } catch (ExpiredJwtException exception) {
            log.error("Token Expired");
            return false;
        } catch (JwtException exception) {
            log.error("Token Tampered", exception);
            return false;
        } catch(NullPointerException exception) {
            log.error("Token is null");
            return false;
        }
    }

    /**
     * Header 내에 토큰을 추출합니다.
     *
     * @param header 헤더
     * @return String
     */
    public static String getTokenFormHeader(String header) {
        return header.split(" ")[1];
    }

    /**
     * 토큰의 만료기간을 지정하는 함수
     * @return Calendar
     */
    private static Date createExpiredDate() {
        // 토큰 만료시간은 30일으로 설정
        Calendar c = Calendar.getInstance();
        c.add(Calendar.HOUR, 8);   // 8시간
        // c.add(Calendar.DATE, 1);        // 1일
        return c.getTime();
    }

    /**
     * JWT 의 "헤더" 값을 생성해주는 메서드
     *
     * @return HashMap<String, Object>
     */
    private static Map<String, Object> createHeader() {
        Map<String, Object> header = new HashMap<>();

        header.put("typ", "JWT");
        header.put("alg", "HS256");
        header.put("regDate", System.currentTimeMillis());
        return header;
    }

    /**
     * 사용자 정보를 기반으로 클래임을 생성해주는 메서드
     *
     * @param userDto 사용자 정보
     * @return Map<String, Object>
     */
    private static Map<String, Object> createClaims(UserDto userDto) {
        // 공개 클레임에 사용자의 이름과 이메일을 설정하여 정보를 조회할 수 있다.
        Map<String, Object> claims = new HashMap<>();

        log.info("userId : {}", userDto.getUserId());
        log.info("userNm : {}", userDto.getUserNm());

        claims.put("userId", userDto.getUserId());
        claims.put("userNm", userDto.getUserNm());
        return claims;
    }

    /**
     * JWT "서명(Signature)" 발급을 해주는 메서드
     *
     * @return Key
     */
    private static Key createSignature() {
        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(jwtSecretKey);
        return new SecretKeySpec(apiKeySecretBytes, SignatureAlgorithm.HS256.getJcaName());
    }

    /**
     * 토큰 정보를 기반으로 Claims 정보를 반환받는 메서드
     * @param token : 토큰
     * @return Claims : Claims
     */
    private static Claims getClaimsFormToken(String token) {
        return Jwts.parser().setSigningKey(DatatypeConverter.parseBase64Binary(jwtSecretKey))
                .parseClaimsJws(token).getBody();
    }

    /**
     * 토큰을 기반으로 사용자 아이디를 반환받는 메서드
     * @param token : 토큰
     * @return String : 사용자 아이디
     */
    public static String getUserIdFormToken(String token) {
        Claims claims = getClaimsFormToken(token);
        return claims.get("userId").toString();
    }

    /**
     * 토큰을 기반으로 사용자 닉네임을 반환받는 메서드
     * @param token : 토큰
     * @return String : 사용자 닉네임
     */
    public static String getUserNmFormToken(String token) {
        Claims claims = getClaimsFormToken(token);
        return claims.get("userNm").toString();
    }
}
```

> ## JwtAuthorizationFilter 추가
> - 지정한 URL 별 JWT 유효성 검증을 수행하며 직접적인 사용자 '인증'을 확인한다.
```Java
@Slf4j
public class JwtAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 1. 토큰이 필요하지 않은 API URL 에 대해서 배열로 구성합니다.
        List<String> list = Arrays.asList(
                "/api/user/login",  // 로그인
                "/api/test/generateToken",
                "/api/user/signup", // 회원가입
                "/api/user/duplicheck" // 회원가입 하위 사용 가능 ID 확인
        );

        // 2. 토큰이 필요하지 않은 API URL 의 경우 => 로직 처리 없이 다음 필터로 이동
        if(list.contains(request.getRequestURI())) {
            filterChain.doFilter(request, response);
            return;
        }

        // 3. OPTIONS 요청일 경우 => 로직 처리 없이 다음 필터로 이동
        if (request.getMethod().equalsIgnoreCase("OPTIONS")) {
            filterChain.doFilter(request, response);
            return;
        }

        // [STEP1] Client 에서 API 를 요청할 때 Header 를 확인합니다.
        String header = request.getHeader(AuthConstants.AUTH_HEADER);
        log.debug("[+] header Check: {}", header);

        try {
            // [STEP2-1] Header 내에 토큰이 존재하는 경우
            if(header != null && !header.equalsIgnoreCase("")) {

                // [STEP2] Header 내에 토큰을 추출합니다.
                String token = TokenUtils.getTokenFormHeader(header);

                // [STEP3] 추출한 토큰이 유효한지 여부를 체크합니다.
                if(TokenUtils.isValidToken(token)) {

                    // [STEP4] 토큰을 기반으로 사용자 아이디를 반환 받는 메서드
                    String userId = TokenUtils.getUserIdFormToken(token);
                    log.debug("[+] userId Check: {}", userId);

                    // [STEP5] 사용자 아이디가 존재하는지 여부 체크
                    if(userId != null && !userId.equalsIgnoreCase("")) {
                        filterChain.doFilter(request, response);
                    } else {
                        // 사용자 아이디가 존재 하지 않을 경우
                        throw new BusinessExceptionHandler("TOKEN isn't userId", ErrorCode.BUSINESS_EXCEPTION_ERROR);
                    }
                } else {
                    // 토큰이 유효하지 않은 경우
                    throw new BusinessExceptionHandler("TOKEN is invalid", ErrorCode.BUSINESS_EXCEPTION_ERROR);
                }
            }
            else {
                // [STEP2-1] 토큰이 존재하지 않는 경우
                throw new BusinessExceptionHandler("Token is null", ErrorCode.BUSINESS_EXCEPTION_ERROR);
            }
        } catch (Exception e) {
            // Token 내에 Exception 이 발생 하였을 경우 => 클라이언트에 응답값을 반환하고 종료합니다.
            response.setCharacterEncoding("UTF-8");
            response.setContentType("application/json");
            PrintWriter printWriter = response.getWriter();
            JSONObject jsonObject = jsonResponseWrapper(e);
            printWriter.print(jsonObject);
            printWriter.flush();
            printWriter.close();
        }
    }

    /**
     * 토큰 관련 Exception 발생 시 예외 응답값 구성
     * @param e Exception
     * @return JSONObject
     */
    private JSONObject jsonResponseWrapper(Exception e) {
        String resultMsg = "";

        // JWT 토큰 만료
        if(e instanceof ExpiredJwtException) {
            resultMsg = "TOKEN Expired";
        }
        // JWT 허용된 토큰이 아님
        else if(e instanceof SignatureException) {
            resultMsg = "TOKEN SignatureException Login";
        }
        // JWT 토큰내에서 오류 발생 시
        else if(e instanceof JwtException) {
            resultMsg = "TOKEN Parsing JwtException";
        }
        // 이외 JWT 토큰내에서 오류 발생
        else {
            resultMsg = "OTHER TOKEN ERROR";
        }

        HashMap<String, Object> jsonMap = new HashMap<>();
        jsonMap.put("status", 401);
        jsonMap.put("code", "9999");
        jsonMap.put("message", resultMsg);
        jsonMap.put("reason", e.getMessage());
        JSONObject jsonObject = new JSONObject(jsonMap);
        log.error(resultMsg, e);
        return jsonObject;
    }
}
```

> ## WebSecurityConfig JWT 관련 코드 추가
```Java
@Bean
 public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
     log.debug("[+] WebSecurityConfig Start !");

     http
             // [STEP1] 서버에 인증정보를 저장하지 않기에 csrf 를 사용하지 않는다.
             .csrf().disable()

             // [STEP2] 토큰을 활용하는 경우 모든 요청에 대해 '인가'에 대해서 적용
             .authorizeHttpRequests(authz -> authz.anyRequest().permitAll())

             // [STEP3] Spring Security JWT Filter Load
             .addFilterBefore(jwtAuthorizationFilter(), BasicAuthenticationFilter.class) // ** 추가 **

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
  * 10. JWT 토큰을 통하여서 사용자를 인증합니다.
  * @return JwtAuthorizationFilter
  */
 @Bean
 public JwtAuthorizationFilter jwtAuthorizationFilter() {
     return new JwtAuthorizationFilter();
 }
```

> ## TestController 작성
```Java
@Slf4j
@RestController
@RequestMapping("api/test")
public class TestController {

    @PostMapping("/generateToken")
    @Operation(summary = "토큰 발급", description = "사용자 정보를 기반으로 JWT 를 발급하는 API")
    public ResponseEntity<ApiResponse> selectCodeList(@RequestBody UserDto userDto) {
        String resultToken = TokenUtils.generateJwtToken(userDto);

        ApiResponse ar = ApiResponse.builder()
                // BEARER {토큰} 형태로 반환을 해줍니다.
                .result(AuthConstants.TOKEN_TYPE + " " + resultToken)
                .resultCode(SuccessCode.SELECT_SUCCESS.getStatus())
                .resultMsg(SuccessCode.SELECT_SUCCESS.getMessage())
                .build();

        return new ResponseEntity<>(ar, HttpStatus.OK);
    }
}
```

> ## .../api/test/generateToken URL에 Front에서 Back 서버로 요청 및 응답 확인
- HTTP Body JSON 이미지
<img src="https://github.com/nineto6/BE-Login/blob/main/md_resource/fe_resource_02.png">

> ## ...api/user/login URL에 Front에서 Back 서버로 요청 및 응답 확인시 문제 발생
- HTTP 응답시 Authorization JWT 토큰의 헤더 값을 받지 못하는 상황 발생
<br/>
<hr/>

##### 20230506
> ## WebSecurityConfig의 corsConfigurationSource()에 코드 추가
- configuration.addExposedHeader(AuthConstants.AUTH_HEADER);

> ## 개발 전용 SSL 인증 추가

> ## ssl-local.properties 작성
```Text
# SSL (https)
server.ssl.key-store=C:/Program Files/Java/jdk-17/bin/nineto6-keystore.p12
server.ssl.key-store-type=PKCS12
server.ssl.key-store-password=123456
server.ssl.key-alias=nineto6-keystore
server.http2.enabled=true
```
> ## LoginApplication에 Annotation 추가
```Java
@PropertySource("classpath:ssl-local.properties")
```

> ## 문제 해결
- 응답시 Front에서 브라우저로 헤더값 확인 이미지
<img src="https://github.com/nineto6/BE-Login/blob/main/md_resource/fe_resource_01.png">
<br/>
<hr/>

##### 20230509
> ## Board 스키마 작성
```SQL
create table tb_board(
   board_sq       int auto_increment primary key,
   user_nm        varchar(20) not null,
   board_title    varchar(30) not null,
   board_content  varchar(1000) not null
);
```
> ## UserMapper Insert 추가 (회원가입)
```Java
@Mapper
public interface UserMapper {
    void save(UserDto userDto); // 추가
    Optional<UserDto> login(UserDto userDto);
}
```
- UserMapper XML 추가
```XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">

<mapper namespace="hello.Login.mapper.UserMapper">

    <!-- 회원가입 추가 -->
    <insert id="save" useGeneratedKeys="true" keyProperty="userSq">
        INSERT INTO TB_USER
        (USER_ID, USER_PW, USER_NM, USER_ST)
        VALUES (#{userId}, #{userPw}, #{userNm}, #{userSt})
    </insert>

    <!-- 로그인 -->
    <select id="login" resultType="hello.Login.model.UserDto">
        SELECT t1.*
        FROM tb_user t1
        WHERE user_id = #{userId}
    </select>
</mapper>
```

> ## UserMapperTest 작성
```Java
@SpringBootTest
@Transactional
@Slf4j
class UserMapperTest {

    @Autowired UserMapper userMapper;

    @Test
    void save() {
        //given
        UserDto user = UserDto.builder()
                .userId("hello123")
                .userPw("123123")
                .userNm("헬로")
                .userSt("X")
                .build();

        // when
        userMapper.save(user);
        log.info("userSq = {}", user.getUserSq());

        // then
        Optional<UserDto> login = userMapper.login(user);

        log.info("login is empty = {}", login.isEmpty());
        Assertions.assertThat(login.isEmpty()).isFalse();
    }
}
```
<br/>
<hr/>

##### 20230510
> ## TokenUtils의 토큰을 기반으로 사용자 닉네임을 반환받는 메서드 작성
```Java
/**
     * @param token : 토큰
     * @return String : 사용자 닉네임
     */
    public static String getUserNmFormToken(String token) {
        Claims claims = getClaimsFormToken(token);
        return claims.get("userNm").toString();
    }
```
<br/>
<hr/>

##### 20230511
> ## BoardDto 작성
```Java
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class BoardDto {
    private int boardSq;
    private String userNm;
    private String boardTitle;
    private String boardContent;

    @Builder
    public BoardDto(int boardSq, String userNm, String boardTitle, String boardContent) {
        this.boardSq = boardSq;
        this.userNm = userNm;
        this.boardTitle = boardTitle;
        this.boardContent = boardContent;
    }
}
```

> ## BoardMapper 작성
```Java
@Mapper
public interface BoardMapper {
    void save(BoardDto boardDto);
    List<BoardDto> findAll();
}

```
- BoardMapper XML 작성
```XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">

<mapper namespace="hello.Login.mapper.BoardMapper">

    <insert id="save" useGeneratedKeys="true" keyProperty="boardSq">
        INSERT INTO TB_BOARD
        (USER_NM, BOARD_TITLE, BOARD_CONTENT)
        VALUES (#{userNm}, #{boardTitle}, #{boardContent})
    </insert>

    <!-- 전체 조회 -->
    <select id="findAll" resultType="hello.Login.model.BoardDto">
        SELECT t1.*
        FROM tb_board t1
    </select>
</mapper>
```

> ## BoardMapperTest 작성
```Java
@SpringBootTest
@Transactional
@Slf4j
class BoardMapperTest {
    @Autowired BoardMapper boardMapper;

    @Test
    @DisplayName("게시글 저장 테스트")
    void save() {
        // given

        BoardDto boardDto = BoardDto.builder()
                .userNm("홍길동")
                .boardTitle("안녕하세요")
                .boardContent("안녕하세요 첫 게시글입니다.")
                .build();

        // when
        boardMapper.save(boardDto);

        //then
        List<BoardDto> list = boardMapper.findAll();
        assertThat(list.get(0).getBoardSq()).isEqualTo(boardDto.getBoardSq());
        assertThat(list.get(0).getUserNm()).isEqualTo("홍길동");
        assertThat(list.get(0).getBoardTitle()).isEqualTo("안녕하세요");
        assertThat(list.get(0).getBoardContent()).isEqualTo("안녕하세요 첫 게시글입니다.");
    }

    @Test
    @DisplayName("게시글 모두 조회 테스트")
    void findAll() {
        UserDto user = UserDto.builder().build();
        // given
        BoardDto boardDto1 = BoardDto.builder()
                .userNm("홍길동")
                .boardTitle("안녕하세요")
                .boardContent("안녕하세요 첫번 째 게시글입니다.")
                .build();
        BoardDto boardDto2 = BoardDto.builder()
                .userNm("길동이")
                .boardTitle("안녕")
                .boardContent("안녕하세요 두번 째 게시글입니다.")
                .build();

        boardMapper.save(boardDto1);
        boardMapper.save(boardDto2);

        // when
        List<BoardDto> listBoard = boardMapper.findAll();

        // then
        assertThat(listBoard.size()).isEqualTo(2);
    }
}
```

> ## BoardService 인터페이스 작성
```Java
public interface BoardService {
    BoardDto create(BoardDto boardDto);
    List<BoardDto> findList();
}
```

> ## BoardService의 구현체 BoardServiceImpl 작성
```Java
@Service
@AllArgsConstructor
public class BoardServiceImpl implements BoardService{
    private final BoardMapper boardMapper;

    @Override
    @Transactional
    public BoardDto create(BoardDto boardDto) {
        boardMapper.save(boardDto);
        return boardDto;
    }

    @Override
    @Transactional(readOnly = true)
    public List<BoardDto> findList() {
        return boardMapper.findAll();
    }
}
```
<br/>
<hr/>

##### 20230512
> ## BoardController REST 컨트롤러 작성
```Java
@RestController
@RequestMapping("/api/board")
@AllArgsConstructor
@Slf4j
public class BoardController {
    private final BoardService boardService;

    @PostMapping
    public ResponseEntity<ApiResponse> createBoard(@RequestBody BoardDto boardDto, HttpServletRequest request) {
        String userNm = TokenUtils.getUserNmFormToken(
                TokenUtils.getTokenFormHeader(
                        request.getHeader(AuthConstants.AUTH_HEADER
                        )));

        BoardDto board = BoardDto.builder()
                .userNm(userNm)
                .boardTitle(boardDto.getBoardTitle())
                .boardContent(boardDto.getBoardContent())
                .build();

        boardService.create(board);

        ApiResponse ar = ApiResponse.builder()
                .result(null)
                .resultCode(SuccessCode.INSERT_SUCCESS.getStatus())
                .resultMsg(SuccessCode.INSERT_SUCCESS.getMessage())
                .build();

        return new ResponseEntity<>(ar, HttpStatus.OK);
    }

    @GetMapping
    public ResponseEntity<ObjectApiResponse> findAllBoard() {

        List<BoardDto> list = boardService.findList();

        ObjectApiResponse ar = ObjectApiResponse.builder()
                .result(list)
                .resultCode(SuccessCode.SELECT_SUCCESS.getStatus())
                .resultMsg(SuccessCode.SELECT_SUCCESS.getMessage())
                .build();

        return new ResponseEntity<>(ar, HttpStatus.OK);
    }
}
```

> ## ObjectApiResponse 작성
- ObjectMapper를 이용하여 기존에 쓰던 ApiResponse의 Result 값으로 들어가게 String으로 변환하여 응답하는 식으로 공통으로 묶을 수 있지만,
- 코드를 간략화하기 위해 ObjectApiResponse를 따로 만들어 Controller의 코드를 단순화 함
```Java
@Getter
public class ObjectApiResponse {
    Object result;
    int resultCode;
    String resultMsg;

    @Builder
    public ObjectApiResponse(Object result, int resultCode, String resultMsg) {
        this.result = result;
        this.resultCode = resultCode;
        this.resultMsg = resultMsg;
    }
}
```
<br/>
<hr/>

##### 20230515
> ## UserService 코드 추가

> ## UserServiceImpl 코드 추가

> ## UserController 작성

> ## ErrorResponse 작성

> ## GlobalExceptionHandler 작성
<br/>
<hr/>

##### 20230516
> ## 테스트

##### 20230522
> ## Secret-Key 별도로 분리 후 관리
- org.springframework.beans.factory.annotation.Value를 이용
- application.properties 에서 jwtSecretKey 값 가져오기
- JwtUtils
```Java
    private static String jwtSecretKey;

    @Value(value = "${custom.jwt-secret-key}")
    public void setKey(String value) {
        jwtSecretKey = value;
    }
```
- application.properties
```Text
# Secret Key
custom.jwt-secret-key=exampleSecretKey
```
> ## 계획
- 현재 토큰 만료 기간이 8시간으로 되어있는데 만일 토큰이 탈취가 됐을 경우
심각한 문제가 발생하게 된다. 그러면 매우 짧은 만료 기간을 가지게 하면 사용자는 매번 토큰이 만료가될 시 로그인을 새로 하여, 새롭게 토큰을 받아야 한다.
- 보안과 사용자의 편리함을 둘다 가져가는 방법을 찾게 되었는데, 찾은것이 Refresh-Token 방식이다.
- Access-Token은 짧게(30분) 만료 기간, Refresh-Token은 길게(3일) 만료기간을 갖는다.
- 서버는 로그인 성공시 Access-Token 과 Refresh-Token을 발급한다.(header에 응답)
    - 이때 Redis(인메모리 데이터 저장소)에 Refresh-Token과 요청한 IP 그리고 userId(토큰 생성시 claim 필요)를 함께 저장한다.
- 클라이언트는 localStorage를 이용하여 Access-Token 과 Refresh-Token을 저장한다.
- 클라이언트는 인증이 필요한 URL 요청시(/api/board GET.. 등) Access-Token을 헤더에 Autorization Bearer 형식으로 넣어서 요청한다.
- 서버는 Access-Token을 받고 인증된 토큰인지 확인 후 처리를 하고 응답한다.
- Access-Token이 만료되었을 경우에는 에러 메세지를 응답하게 된다.
- 클라이언트는 토큰이 만료되었을 경우 .../api/reissue URL에 Refresh-Token을 헤더에 Autorization Bearer 형식으로 넣어서 요청한다.
- 서버는 Refresh-Token을 받고 인증된 토큰인지 확인 후(만료가 되었는지도 확인) Access-Token 과 Refresh-Token을 함께 발급하여 응답한다.(이때 Redis에 새로 발급한 토큰을 Update)
> ## Redis 추가
- build.gradle
```Text
// Redis 추가
implementation 'org.springframework.boot:spring-boot-starter-data-redis'
```
- application.properties
```Text
# Redis
spring.redis.host=localhost
spring.redis.port=6379
```

##### 20230523
> ## RedisConfig 작성
> ## RedisRepository 작성
> ## RefreshToken 작성
> ## JwtToken 작성
> ## TokenUtils 코드 변경

##### 20230524
> ## NetUtils 작성
- HttpServletRequest 정보를 가져와서 header 내에 IP 정보를 String으로 반환하는 메서드 getClinetIp()
> ## AuthConstatns 코드 변경
> ## WebSecurityConfig 코드 변경
> ## CustomAuthSuccessHandler 코드 변경
> ## TestController 코드 변경 및 테스트
> ## AccountController 작성 및 테스트
> ## TokenUtils 코드 변경
> ## CustomAuthSuccessHandler 코드 변경
> ## AccountController 코드 변경