# 🛠️NINETO6 사이드프로젝트 만들기

## 시작하기 전에...
JSON Web Token을 이용하여 REST API 인증 처리를 만들어보려고 한다. 

> 현재 `Front-End` 와 `Back-End` 는 다른 환경에서 개발하고 있음

## 요구사항
어떤 사용자는 어떤 페이지에 접근하기 위해서 로그인이 반드시 필요하다.
이를 위해 이전에 회원가입을 진행하고 로그인을 한 뒤에 해당 페이지에 접근한다.
로그인이 되어 있지 않을 시, 해당 페이지로의 접근은 불가하다.

### 인증 없이 접근 가능한 URL
|기능|URL|
|------|---|
|회원가입|[POST] /api/users/signup|
|로그인|[GET] /api/users/login|
|사용자 아이디 중복 체크|[GET] /api/users/duplicheck?userId=사용자아이디|

### 인증이 있어야 접근 가능한 URL
|기능|URL|
|------|---|
|로그아웃|[GET] /api/users/logout|
|게시글 생성|[POST] /api/board|
|게시글 전체 조회|[GET] /api/board|

### Refresh-Token을 가지고 Access-Token을 재발급하는 URL
|기능|URL|
|------|---|
|재발급|[GET] /api/users/reissue|

## 출처
- ErrorCode, Security, JWT 등을 참고한 사이트 출처 
    - [Contributor9 블로그](https://adjh54.tistory.com/91)
- Refresh-Token, Redis를 참고한 사이트 출처
    - [wildeveloperetrain 블로그](https://wildeveloperetrain.tistory.com/245)
- JWT Logout, Redis를 참고한 사이트 출처
    - [joonghyun 블로그](https://velog.io/@joonghyun/SpringBoot-Jwt%EB%A5%BC-%EC%9D%B4%EC%9A%A9%ED%95%9C-%EB%A1%9C%EA%B7%B8%EC%95%84%EC%9B%83)
    - [wildeveloperetrain 블로그](https://wildeveloperetrain.tistory.com/61)

## 개발 환경
- Project : Gradle
- SpringBoot 버전 : 2.7.11
- Java 버전 : 11
- 초기 Dependencies
   - Spring Web:5.3.27
   - Spring Security:5.7.8
   - Mybatis:3.5.11
   - Lombok:1.18.26
   - H2 Database:2.1.214
- 추가된 Dependencies
   - jwt:0.9.1
   - jaxb-runtime(DataTypeConverter):2.3.2
   - json-simple:1.1.1
   - springdoc-openapi-ui(Swagger):1.6.12
   - Redis:2.7.11
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
- Dependencies 추가
    ```Text
    implementation 'com.googlecode.json-simple:json-simple:1.1.1' // simple-json 추가
    ```
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
- .../api/users/login URL에 Front에서 Back 서버로 요청 및 응답을 확인을 하였으나 HTTP 응답시 CORS 오류 확인
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
- .../api/users/login URL에 Front에서 Back 서버로 요청 및 응답을 확인하여 200 정상 응답코드 확인
- Back 서버에서의 로그 확인 이미지
<img src="https://github.com/nineto6/BE-Login/blob/main/md_resource/be_resource_01.png">
<br/>
<hr/>

##### 20230503
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
> ## AuthConstants 추가
- JWT 관련된 상수로 사용 되는 파일
```Java
public final class AuthConstants {
    public static final String AUTH_HEADER = "Authorization";
    public static final String TOKEN_TYPE = "BEARER";
}
```

> ## TokenUtils 추가
- Dependencies 추가
    ```Text
    implementation 'io.jsonwebtoken:jjwt:0.9.1' // Json-Web-Token
    implementation 'org.glassfish.jaxb:jaxb-runtime:2.3.2' //DataTypeConverter 추가 
    ```
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
- 지정한 URL 별 JWT 유효성 검증을 수행하며 직접적인 사용자 '인증'을 확인한다.
```Java
@Slf4j
public class JwtAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 1. 토큰이 필요하지 않은 API URL 에 대해서 배열로 구성합니다.
        List<String> list = Arrays.asList(
                "/api/users/login",  // 로그인
                "/api/test/generateToken",
                "/api/users/signup", // 회원가입
                "/api/users/duplicheck" // 회원가입 하위 사용 가능 ID 확인
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

> ## WebSecurityConfig JWT 관련 코드 변경 및 추가
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
- Dependencies 추가
    - build.gradle
    ```Text
    - implementation 'org.springdoc:springdoc-openapi-ui:1.6.12' // Swagger 추가
    ```
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
<br> <img src="https://github.com/nineto6/BE-Login/blob/main/md_resource/fe_resource_02.png">

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
- 로그인 성공 응답시 브라우저로 헤더값 확인 이미지
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
    @DisplayName("유저 저장 테스트")
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
        assertThat(login.isEmpty()).isFalse();
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
> ## 계획
- 사용자 인증(토큰 검증)이 되어야지 접근할 수 있는 임시 게시글을 만들기

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
```Java
    public interface UserService {
    Optional<UserDto> login(UserDto userDto);
    void signUp(UserDto userDto); // 추가
}
```

> ## UserServiceImpl 코드 추가
- 회원가입
```Java
@Override
    @Transactional
    public void signUp(UserDto userDto) {
        Optional<UserDto> selectedUserDto = userMapper.login(userDto);
        if(selectedUserDto.isEmpty()) {
            userMapper.save(userDto);
            return;
        }
        throw new BusinessExceptionHandler(ErrorCode.INSERT_ERROR,getMessage(), ErrorCode.INSERT_ERROR);
    }
```

> ## UserController 작성
```Java
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/users")
@Slf4j
public class UserController {
    private final UserService userService;

    /**
     * UserId, UserPw, UserNm 을 받아서 회원가입
     * @param userDto
     * @return ResponseEntity
     * 언체크 예외
     * @throws BusinessExceptionHandler
     */
    @PostMapping("/signup")
    public ResponseEntity<ApiResponse> signUp(@RequestBody UserDto userDto) {

        UserDto user = UserDto.builder()
                .userId(userDto.getUserId())
                .userPw(userDto.getUserPw())
                .userNm(userDto.getUserNm())
                .userSt("X")
                .build();

        userService.signUp(user);

        ApiResponse success = ApiResponse.builder()
                .result(SuccessCode.INSERT_SUCCESS.getCode())
                .resultCode(SuccessCode.INSERT_SUCCESS.getStatus())
                .resultMsg(SuccessCode.INSERT_SUCCESS.getMessage())
                .build();

        return new ResponseEntity<>(success, HttpStatus.OK);
    }

    /**
     * userId 값을 받아와서 사용 가능한 Id 체크 (가능 true, 불가능 false)
     * @param userId
     * @return ResponseEntity
     */
    @GetMapping("/duplicheck")
    public ResponseEntity<ApiResponse> duplicateCheck(@RequestParam String userId) {
        UserDto checkUserId = UserDto.builder()
                .userId(userId)
                .build();

        Optional<UserDto> findByIdDto = userService.login(checkUserId);

        ApiResponse ar = ApiResponse.builder()
                .result((findByIdDto.isEmpty()) ? "true" : "false")
                .resultCode(SuccessCode.SELECT_SUCCESS.getStatus())
                .resultMsg(SuccessCode.SELECT_SUCCESS.getMessage())
                .build();

        return new ResponseEntity<>(ar, HttpStatus.OK);
    }
}
```

> ## ErrorResponse 작성
```Java
@Getter
public class ErrorResponse {
    String result;
    int resultCode;
    String resultMsg;
    String reason;

    @Builder
    public ErrorResponse(String result, int resultCode, String resultMsg, String reason) {
        this.result = result;
        this.resultCode = resultCode;
        this.resultMsg = resultMsg;
        this.reason = reason;
    }
}
```

> ## GlobalExceptionHandler 작성
```Java
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {
    /**
     * BusinessException 예외 처리
     * @param ex
     * @return ResponseEntity
     */
    @ExceptionHandler(BusinessExceptionHandler.class)
    public ResponseEntity<ErrorResponse> businessExHandler(BusinessExceptionHandler ex) {
        log.error("[exceptionHandler] ex", ex);

        ErrorResponse er = ErrorResponse.builder()
                .result(ErrorCode.BUSINESS_EXCEPTION_ERROR.getDivisionCode())
                .resultCode(ErrorCode.BUSINESS_EXCEPTION_ERROR.getStatus())
                .resultMsg(ErrorCode.BUSINESS_EXCEPTION_ERROR.getMessage())
                .reason(ex.getMessage())
                .build();

        return new ResponseEntity<>(er, HttpStatus.OK);
    }
}
```

> ## 실행 결과
- 회원가입 로그 이미지
<br> <img src="https://github.com/nineto6/BE-Login/blob/main/md_resource/be_resource_06.png">
- 로그인 로그 이미지
<br> <img src="https://github.com/nineto6/BE-Login/blob/main/md_resource/be_resource_05.png">
- JwtAuthorizationFilter에서 인증이 되어야지 BoardController에 접근할 수 있다.
- POST 게시글 등록 로그 이미지
<br> <img src="https://github.com/nineto6/BE-Login/blob/main/md_resource/be_resource_03.png">
- GET 게시글 모두 조회 이미지
<br> <img src="https://github.com/nineto6/BE-Login/blob/main/md_resource/be_resource_04.png">

<br/>
<hr/>

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
- 현재 토큰 만료 기간이 8시간으로 되어있는데 만일 토큰이 탈취가 됐을 경우 심각한 문제가 발생하게 된다. 그리고 매우 짧은 만료 기간을 가지게 되면 사용자는 매번 토큰이 만료가될 시 로그인을 계속 해야된다는 불편함을 갖고있다.
- 보안과 사용자의 편리함을 둘다 가져가는 방법을 찾게 되었는데, 찾은것이 Refresh-Token 방식이다.
- Access-Token은 짧게(30분) 만료 기간, Refresh-Token은 길게(3일) 만료기간을 갖는다.
- 서버는 로그인 성공시 Access-Token 과 Refresh-Token을 발급한다.(header에 응답)
    - 이때 Redis(인메모리 데이터 저장소)에 Refresh-Token과 요청한 IP 그리고 userId(토큰 생성시 claim 필요)를 함께 저장한다.
- 클라이언트는 localStorage를 이용하여 Access-Token 과 Refresh-Token을 저장한다.
- 클라이언트는 인증이 필요한 URL 요청시(/api/board GET.. 등) Access-Token을 헤더에 Autorization Bearer 형식으로 넣어서 요청한다.
- 서버는 Access-Token을 받고 인증된 토큰인지 확인 후 처리를 하고 응답한다.
- Access-Token이 만료되었을 경우에는 에러 메세지를 응답하게 된다.(401와 함께 Token Expired)
- 클라이언트는 토큰이 만료되었을 경우 .../api/reissue URL에 Refresh-Token을 헤더에 Autorization Bearer 형식으로 넣어서 요청한다.
- 서버는 Refresh-Token을 받고 인증된 토큰인지 확인 후(만료가 되었는지도 확인) Refresh-Token을 Redis에 조회하여 Request 된 IP와  조회된 IP를 비교 후 같은 IP일 경우 Access-Token 과 Refresh-Token을 함께 발급하여 응답한다.(이때 Redis에 새로 발급한 토큰을 Update) 

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
<br/>
<hr/>

##### 20230523
> ## RedisConfig 작성
```Java
@EnableRedisRepositories
@Configuration
public class RedisConfig {
    @Value("${spring.redis.host}")
    private String redisHost;

    @Value("${spring.redis.port}")
    private int redisPort;

    @Bean
    public RedisConnectionFactory redisConnectionFactory() {
        return new LettuceConnectionFactory(redisHost, redisPort);
    }

    @Bean
    public RedisTemplate<String, String> redisTemplate() {
        RedisTemplate<String, String> redisTemplate = new RedisTemplate<>();
        redisTemplate.setKeySerializer(new StringRedisSerializer());
        redisTemplate.setValueSerializer(new StringRedisSerializer());
        redisTemplate.setConnectionFactory(redisConnectionFactory());
        return redisTemplate;
    }
}
```

> ## RedisRepository 작성
- CrudRepository를 상속하는 CustomInterface를 생성
- redisRepository 방식은 CrudRepository를 상속받은 인터페이스가 사용되기 때문에 Spring Data JPA에서 JpaRepository를 사용하는 방식과 유사하다는 특징이 있다.
```Java
public interface RedisRepository extends CrudRepository<RefreshToken, Long> {
    RefreshToken findByRefreshToken(String refreshToken);
}
```

> ## RefreshToken 작성
```Java
@Builder
@Getter
@AllArgsConstructor
@NoArgsConstructor
@RedisHash(value = "refresh", timeToLive = 1209600)
public class RefreshToken {
    @Id // null 로 저장될 경우 랜덤 값으로 설정된다. (UUID)
    private String id;

    private String ip;

    private UserDto userDto;

    @Indexed // Secondary indexes(보조 인덱스) 적용
    private String refreshToken;
}
```

> ## JwtToken 작성
```Java
@Builder
@Getter
@AllArgsConstructor
public class JwtToken {
    private String AccessToken;
    private String RefreshToken;
}
```

> ## TokenUtils 코드 변경
- 다음에 개선 해야 하는 사항
    - Access-Token 과 Refresh-Token이 subject 및 Claims 구성이 똑같기 때문에 보안적으로 안좋다.
```Java
@Slf4j
@Component
public class TokenUtils {

    private static String accessSecretKey;
    private static String refreshSecretKey;

    // application.properties 에서 accessSecretKey 값 가져오기
    @Value(value = "${custom.jwt-access-secret-key}")
    public void accessSecretKey(String key) {
        accessSecretKey = key;
    }

    // application.properties 에서 refreshSecretKey 값 가져오기
    @Value(value = "${custom.jwt-refresh-secret-key}")
    public void setRefreshSecretKey(String key) {
        refreshSecretKey = key;
    }

    /**
     * 사용자 정보를 기반으로 토큰을 생성하여 반환 해주는 메서드
     * @param userDto UserDto : 사용자 정보
     * @return JwtToken(accessToken, refreshToken) 토큰
     */
    public static JwtToken generateJwtToken(UserDto userDto) {
        // 사용자 시퀀스를 기준으로 JWT 토큰을 발급하여 반환해줍니다.
        JwtBuilder accessBuilder = Jwts.builder()
                .setHeader(createHeader())                                             // Header 구성
                .setClaims(createAccessClaims(userDto))                                // Payload - Claims 구성
                .setSubject(String.valueOf(userDto.getUserSq()))                       // Payload - Subject 구성
                .signWith(SignatureAlgorithm.HS256, createSignature(accessSecretKey))  // Signature 구성
                .setExpiration(createAccessTokenExpiredDate());                        // Expired Date 구성

        JwtBuilder refreshBuilder = Jwts.builder()
                .setHeader(createHeader())                                             // Header 구성
                .setClaims(createRefreshClaims(userDto))                               // Payload - Claims 구성
                .setSubject(String.valueOf(userDto.getUserSq()))                       // Payload - Subject 구성
                .signWith(SignatureAlgorithm.HS256, createSignature(refreshSecretKey)) // Signature 구성
                .setExpiration(createRefreshTokenExpiredDate());                       // Expired Date 구성

        return JwtToken.builder()
                .AccessToken(accessBuilder.compact())
                .RefreshToken(refreshBuilder.compact())
                .build();
    }

    /**
     * 엑세스 토큰을 기반으로 사용자 정보를 반환 해주는 메서드
     * @param token String : 토큰
     * @return String : 사용자 정보
     */
    public static String parseAccessTokenToUserInfo(String token) {
        return Jwts.parser()
                .setSigningKey(accessSecretKey)
                .parseClaimsJwt(token)
                .getBody()
                .getSubject();
    }

    /**
     * 유효한 엑세스 토큰인지 확인 해주는 메서드
     * @param token String  : 토큰
     * @return      boolean : 유효한지 여부 반환
     */
    public static boolean isValidAccessToken(String token) {
        try {
            Claims claims = getAccessTokenToClaimsFormToken(token);

            log.info("expireTime : {}", claims.getExpiration());
            log.info("userId : {}", claims.get("uid"));
            log.info("userNm : {}", claims.get("unm"));

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
     * 유효한 리프레쉬 토큰인지 확인 해주는 메서드
     * @param token String  : 토큰
     * @return      boolean : 유효한지 여부 반환
     */
    public static boolean isValidRefreshToken(String token) {
        try {
            Claims claims = getRefreshTokenToClaimsFormToken(token);

            log.info("expireTime : {}", claims.getExpiration());
            log.info("userId : {}", claims.get("uid"));
            log.info("userNm : {}", claims.get("unm"));

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
     * 엑세스 토큰의 만료기간을 지정하는 함수
     * @return Calendar
     */
    private static Date createAccessTokenExpiredDate() {
        Calendar c = Calendar.getInstance();
        c.add(Calendar.MINUTE, 30);   // 30분으로 설정
        return c.getTime();
    }

    /**
     * 리프레쉬 토큰의 만료기간을 지정하는 함수
     * @return Calendar
     */
    private static Date createRefreshTokenExpiredDate() {
        Calendar c = Calendar.getInstance();
        c.add(Calendar.DATE, 3);   // 3일로 설정
        return c.getTime();
    }

    /**
     * JWT 의 "헤더" 값을 생성해주는 메서드
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
     * Access-Token 전용 사용자 정보를 기반으로 클래임을 생성해주는 메서드
     * @param userDto 사용자 정보
     * @return Map<String, Object>
     */
    private static Map<String, Object> createAccessClaims(UserDto userDto) {
        // 공개 클레임에 사용자의 이름과 이메일을 설정하여 정보를 조회할 수 있다.
        // JWT 를 최대한 짧게 만들기 위해 클레임네임을 전부 약자로 변경
        // 클레임셋의 내용이 많아지면 토큰의 길이도 같이 길어지기 때문에 되도록 최소화한다.
        Map<String, Object> claims = new HashMap<>();

        log.info("userId : {}", userDto.getUserId());
        log.info("userNm : {}", userDto.getUserNm());

        claims.put("uid", userDto.getUserId());
        claims.put("unm", userDto.getUserNm());
        return claims;
    }

    /**
     * Refresh-Token 전용 사용자 정보를 기반으로 클래임을 생성해주는 메서드
     * @param userDto 사용자 정보
     * @return Map<String, Object>
     */
    private static Map<String, Object> createRefreshClaims(UserDto userDto) {
        // 공개 클레임에 사용자의 이름과 이메일을 설정하여 정보를 조회할 수 있다.
        // JWT 를 최대한 짧게 만들기 위해 클레임네임을 전부 약자로 변경
        // 클레임셋의 내용이 많아지면 토큰의 길이도 같이 길어지기 때문에 되도록 최소화한다.
        Map<String, Object> claims = new HashMap<>();

        log.info("userId : {}", userDto.getUserId());
        log.info("userNm : {}", userDto.getUserNm());

        claims.put("uid", userDto.getUserId());
        claims.put("unm", userDto.getUserNm());
        return claims;
    }

    /**
     * JWT "서명(Signature)" 발급을 해주는 메서드
     * @return Key
     */
    private static Key createSignature(String key) {
        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(key);
        return new SecretKeySpec(apiKeySecretBytes, SignatureAlgorithm.HS256.getJcaName());
    }

    /**
     * 엑세스 토큰 정보를 기반으로 Claims 정보를 반환받는 메서드
     * @param token : 토큰
     * @return Claims : Claims
     */
    private static Claims getAccessTokenToClaimsFormToken(String token) {
        return Jwts.parser().setSigningKey(DatatypeConverter.parseBase64Binary(accessSecretKey))
                .parseClaimsJws(token).getBody();
    }

    /**
     * 리프레쉬 토큰 정보를 기반으로 Claims 정보를 반환받는 메서드
     * @param token : 토큰
     * @return Claims : Claims
     */
    private static Claims getRefreshTokenToClaimsFormToken(String token) {
        return Jwts.parser().setSigningKey(DatatypeConverter.parseBase64Binary(refreshSecretKey))
                .parseClaimsJws(token).getBody();
    }


    /**
     * 엑세스 토큰을 기반으로 사용자 아이디를 반환받는 메서드
     * @param token : 토큰
     * @return String : 사용자 아이디
     */
    public static String getUserIdFormAccessToken(String token) {
        Claims claims = getAccessTokenToClaimsFormToken(token);
        return claims.get("uid").toString();
    }

    /**
     * 엑세스 토큰을 기반으로 사용자 닉네임을 반환받는 메서드
     * @param token : 토큰
     * @return String : 사용자 닉네임
     */
    public static String getUserNmFormAccessToken(String token) {
        Claims claims = getAccessTokenToClaimsFormToken(token);
        return claims.get("unm").toString();
    }
}
```
<br/>
<hr/>

##### 20230524
> ## NetUtils 작성
- HttpServletRequest 정보를 가져와서 header 내에 IP 정보를 String으로 반환하는 메서드 getClinetIp()
```Java
public class NetUtils {
    public static String getClientIp(HttpServletRequest request) {
        String clientIp = null;
        boolean isIpInHeader = false;

        List<String> headerList = new ArrayList<>();
        headerList.add("X-Forwarded-For"); // (X-Forwarded-For (XFF) - HTTP 프록시나 로드 밸런서를 통해 웹 서버에 접속하는 클라이언트의 원 IP 주소를 식별하는 표준 헤더)
        headerList.add("HTTP_CLIENT_IP");
        headerList.add("HTTP_X_FORWARDED_FOR");
        headerList.add("HTTP_X_FORWARDED");
        headerList.add("HTTP_FORWARDED_FOR");
        headerList.add("HTTP_FORWARDED");
        headerList.add("Proxy-Client-IP");
        headerList.add("WL-Proxy-Client-IP");
        headerList.add("HTTP_VIA");
        headerList.add("IPV6_ADR");

        for (String header : headerList) {
            clientIp = request.getHeader(header);
            if (StringUtils.hasText(clientIp) && !clientIp.equals("unknown")) {
                isIpInHeader = true;
                break;
            }
        }

        if (!isIpInHeader) {
            clientIp = request.getRemoteAddr();
        }

        return clientIp;
    }
}
```

> ## AuthConstatns 코드 변경
```Java
public final class AuthConstants {
    public static final String AUTH_HEADER = "Authorization";
    public static final String AUTH_ACCESS = "Access-Token"; // 추가
    public static final String AUTH_REFRESH = "Refresh-Token"; // 추가
    public static final String TOKEN_TYPE = "BEARER";
}
```

> ## WebSecurityConfig 코드 변경 (추가된 부분)
```Java
public class WebSecurityConfig {
    private final RedisRepository redisRepository; // 추가

    @Bean
    public CustomAuthSuccessHandler customLoginSuccessHandler() {
        return new CustomAuthSuccessHandler(redisRepository); // 추가(의존관계 주입)
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.addAllowedOrigin("https://localhost:3000/");
        configuration.addAllowedHeader("*");
        configuration.addAllowedMethod("*");
        configuration.setAllowCredentials(true);
        configuration.addExposedHeader(AuthConstants.AUTH_HEADER);
        configuration.addExposedHeader(AuthConstants.AUTH_ACCESS); // 추가
        configuration.addExposedHeader(AuthConstants.AUTH_REFRESH); // 추가

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
```

> ## CustomAuthSuccessHandler 코드 변경
```Java
@Slf4j
@Configuration
@RequiredArgsConstructor // 추가
public class CustomAuthSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private final RedisRepository refreshTokenRedisRepository; // 추가

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws ServletException, IOException {
        log.debug("3. CustomLoginSuccessHandler");

        // [STEP1] 사용자와 관련된 정보를 모두 조회합니다.
        UserDto userDto = ((UserDetailsDto) authentication.getPrincipal()).getUserDto();

        // [STEP2] 조회한 데이터를 JSONObject 형태로 파싱을 수행합니다.
        // 문제점 발생 지점
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

            // *** 변경 부분 ***
            // TODO: 추후 JWT 발급에 사용할 예정
            JwtToken jwtToken = TokenUtils.generateJwtToken(userDto);
            response.addHeader(AuthConstants.AUTH_ACCESS, jwtToken.getAccessToken());
            response.addHeader(AuthConstants.AUTH_REFRESH, jwtToken.getRefreshToken());

            // Redis 정보 저장
            refreshTokenRedisRepository.save(RefreshToken.builder()
                    .id(null)
                    .ip(NetUtils.getClientIp(request))
                    .userId(userDto.getUserId())
                    .refreshToken(jwtToken.getRefreshToken())
                    .build());
            //log.info("IP : {}", NetUtils.getClientIp(request)); // 클라이언트 IP 확인 로그
            // *****************
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

> ## TestController 코드 변경 및 테스트
```Java
@Slf4j
@RestController
@RequestMapping("api/test")
public class TestController {

    @PostMapping("/generateToken")
    @Operation(summary = "토큰 발급", description = "사용자 정보를 기반으로 JWT 를 발급하는 API")
    public ResponseEntity<ApiResponse> selectCodeList(@RequestBody UserDto userDto) {
        JwtToken jwtToken = TokenUtils.generateJwtToken(userDto); // 변경

        ApiResponse ar = ApiResponse.builder()
                // BEARER {토큰} 형태로 반환을 해줍니다.
                .result("Access-Token"  + " " + jwtToken.getAccessToken()
                        + "Refresh-Token" + " " + jwtToken.getRefreshToken()) // 변경
                .resultCode(SuccessCode.SELECT_SUCCESS.getStatus())
                .resultMsg(SuccessCode.SELECT_SUCCESS.getMessage())
                .build();

        return new ResponseEntity<>(ar, HttpStatus.OK);
    }
}
```

> ## UserControler 코드 추가 및 테스트
- Refresh-Token 유효성 검사 및 IP 확인 후 Access-Token, Refresh-Token 재 발급 
```Java
public class UserController {
    private final RedisRepository refreshTokenRedisRepository;
    private final UserService userService;

    // ... 코드 생략

    // -------------------  추가 부분  ------------------
    /**
     *  Refresh-Token 으로 부터 재발급 (JwtAuthorizationFilter 인증 X)
     * @param request (Authorization : BEARER Refresh-Token)
     * @param response
     * @return ResponseEntity
     */
    @GetMapping("/reissue")
    public ResponseEntity<ApiResponse> reissue(HttpServletRequest request, HttpServletResponse response) {
        // 1. Request 에서 Header 추출
        String header = request.getHeader(AuthConstants.AUTH_HEADER);

        // 2. Header 에서 JWT Refresh Token 추출
        String token = TokenUtils.getTokenFormHeader(header);

        // 3. validateToken 메서드로 토큰 유효성 검사
        if (token != null && TokenUtils.isValidRefreshToken(token)) {
            // 4. 저장된 refresh token 찾기
            RefreshToken refreshToken = refreshTokenRedisRepository.findByRefreshToken(token);

            if (refreshToken != null) {
                // 5. 최초 로그인한 ip와 같은지 확인 (처리 방식에 따라 재발급을 하지 않거나 메일 등의 알림을 주는 방법이 있음)
                String currentIpAddress = NetUtils.getClientIp(request);

                if (refreshToken.getIp().equals(currentIpAddress)) {

                    // findById 실행 후 userDto 값 가져오기
                    Optional<UserDto> userDto = userService.login(UserDto.builder()
                            .userId(refreshToken.getUserId())
                            .build());

                    if(userDto.isPresent()) { // userDto 값이 있을 경우 (null 이 아닌 경우)
                        // 6. Redis 에 저장된 RefreshToken 정보를 기반으로 JWT Token 생성
                        JwtToken jwtToken = TokenUtils.generateJwtToken(userDto.get());
                        response.addHeader(AuthConstants.AUTH_ACCESS, jwtToken.getAccessToken());
                        response.addHeader(AuthConstants.AUTH_REFRESH, jwtToken.getRefreshToken());

                        // 7. Redis RefreshToken update
                        refreshTokenRedisRepository.save(RefreshToken.builder()
                                .id(refreshToken.getId())
                                .ip(currentIpAddress)
                                .userId(refreshToken.getUserId())
                                .refreshToken(jwtToken.getRefreshToken())
                                .build());

                        ApiResponse ar = ApiResponse.builder()
                                .result("Reissue Success") // 재발급 성공
                                .resultCode(SuccessCode.UPDATE_SUCCESS.getStatus())
                                .resultMsg(SuccessCode.UPDATE_SUCCESS.getMessage())
                                .build();

                        return new ResponseEntity<>(ar, HttpStatus.OK);
                    }
                }
            }
        }

        ApiResponse ar = ApiResponse.builder()
                .result("It cannot be reissued.") // 재발급 불가
                .resultCode(ErrorCode.BUSINESS_EXCEPTION_ERROR.getStatus())
                .resultMsg(ErrorCode.BUSINESS_EXCEPTION_ERROR.getMessage())
                .build();
        return new ResponseEntity<>(ar, HttpStatus.OK);
    }
```
<br/>
<hr/>

##### 20230525
> ## RefreshToken 코드 변경
- Redis에 저장할 기간을 3일로 지정
- timeToLive : 초 단위
```Java
@Getter
@AllArgsConstructor
@NoArgsConstructor
@RedisHash(value = "refresh", timeToLive = 259200) // 변경 (만료기간 3일로 지정)
public class RefreshToken {
    @Id // null 로 저장될 경우 랜덤 값으로 설정됨
    private String id;

    private String ip;

    private UserDto userDto;
    private String userId;

    @Indexed // Secondary indexes(보조 인덱스) 적용
    private String refreshToken;
}
```

> ## 실행 결과
- 로그인 성공시 Access-Token, Refresh-Token을 발급한 이미지
<br> <img src="https://github.com/nineto6/BE-Login/blob/main/md_resource/be_resource_07.png">
- 재발급을 성공한 응답 이미지
<br> <img src="https://github.com/nineto6/BE-Login/blob/main/md_resource/be_resource_13.png">
- Redis 모니터링 이미지
<br> <img src="https://github.com/nineto6/BE-Login/blob/main/md_resource/be_resource_08.png">
- 클라이언트 IP가 변경 및 Refresh-Token이 변조 되었을 경우 에러 응답 이미지
<br> <img src="https://github.com/nineto6/BE-Login/blob/main/md_resource/be_resource_11.png">

<br/>
<hr/>

##### 20230526
> ## 계획
- 만일 DB가 탈취 됐을 경우 사용자 비밀번호를 그대로 보여주게되어 보안에 매우 취약하다.
- 단방향 해시 알고리즘(bcrypt)을 이용하여 DB에 저장된 암호화된 비밀번호는 복호화가 불가능하게 만든다.
- 클라이언트에서 로그인 요청시에만 비밀번호와 DB에 저장된 암호화된 값과의 비교를 통해 검증을 진행한다.

> ## User 스키마 수정
- user_pw 수정
```SQL
create table tb_user(
   user_sq        int auto_increment primary key,
   user_id         varchar(20) not null,
   user_pw       varchar(20) not null,
   user_pw       varchar(60) not null,  
   user_nm       varchar(20) not null,
   user_st         varchar(1) not null
);
```

> ## CustomAuthenticationProvider 코드 변경
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

        // 'AuthenticationFilter' 에서 생성된 토큰으로부터 아이디와 비밀번호를 조회함
        String userId = token.getName();
        String userPw = (String) token.getCredentials();

        // Spring Security - UserDetailsService 를 통해 DB 에서 아이디로 사용자 조회
        UserDetailsDto userDetailsDto = (UserDetailsDto) userDetailsService.loadUserByUsername(userId);

        // passwordEncoder 를 이용하여 userPw 와 DB 에서 조회한 userDetailsDto.getUserPw(인코딩된) 비밀번호를 비교 (코드 변경)
        if(!(passwordEncoder.matches(userPw, userDetailsDto.getUserPw()))) {
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

> ## UserServiceImpl 코드 변경
```Java
@Service
@Slf4j
@RequiredArgsConstructor
public class UserServiceImpl implements UserService{

    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;

    /**
     * 로그인 구현체
     * @param userDto UserDto
     * @return Optional<UserDto>
     */
    @Override
    public Optional<UserDto> login(UserDto userDto) {
        return userMapper.login(userDto);
    }

    @Override
    @Transactional
    public void signUp(UserDto userDto) {
        // 코드 변경
        UserDto pwEncodedUserDto = UserDto.builder()
                .userId(userDto.getUserId())
                .userPw(passwordEncoder.encode(userDto.getUserPw())) // 중요
                .userNm(userDto.getUserNm())
                .userSt(userDto.getUserSt())
                .build();

        Optional<UserDto> selectedUserDto = userMapper.login(pwEncodedUserDto); // findByUserId

        if(selectedUserDto.isEmpty()) {
            userMapper.save(pwEncodedUserDto);
            return;
        }

        throw new BusinessExceptionHandler(ErrorCode.INSERT_ERROR.getMessage(), ErrorCode.INSERT_ERROR);
    }
}
```

> ## UserController 코드 변경
- NotBlank 추가
```Java
public ResponseEntity<ApiResponse> duplicateCheck(@RequestParam @NotBlank(message = "No spaces are allowed.") String userId) {
```

> ## TokenUtils 코드 변경
```Java
@Slf4j
@Component
public class TokenUtils {

    // ... 코드 생략

    /**
     * 유효한 엑세스 토큰인지 확인 해주는 메서드
     * @param token String  : 토큰
     * @return      boolean : 유효한지 여부 반환
     */
    public static boolean isValidAccessToken(String token) {
        try {
            Claims claims = getAccessTokenToClaimsFormToken(token);

            log.info("expireTime : {}", claims.getExpiration());
            log.info("userId : {}", claims.get("uid"));
            log.info("userNm : {}", claims.get("unm"));

            return true;
        } catch (ExpiredJwtException exception) {
            log.error("Token Expired");ㄴ
            throw exception; // 변경
        } catch (JwtException exception) {
            log.error("Token Tampered", exception);
            return false;
        } catch(NullPointerException exception) {
            log.error("Token is null");
            return false;
        }
    }

    // ... 코드 생략
}
```

> ## JwtAuthorizationFilter 코드 변경
```Java
@Slf4j
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    // ... 코드 생략
    
    private JSONObject jsonResponseWrapper(Exception e) {
        String resultMsg = "";
        
        // *** 코드 추가 시작 ***
        // 만료된 토큰만 resultMsg 에 적용 (프론트 검증시 필요(Refresh-Token 사용하기 위함))
        // JWT 토큰 만료 (사용)
        if(e instanceof ExpiredJwtException) {
            resultMsg = "Token Expired";

            // reason 을 내보내지 않기 위함 (exception 보안 문제)
            HashMap<String, Object> jsonMap = new HashMap<>();
            jsonMap.put("status", 401);
            jsonMap.put("code", "9999");
            jsonMap.put("message", resultMsg);
            // reason X
            JSONObject jsonObject = new JSONObject(jsonMap);
            log.error(resultMsg, e);
            return jsonObject;
        }
        // *** 코드 추가 끝 ***
        
        // JWT 허용된 토큰이 아님
        else if(e instanceof SignatureException) {
            resultMsg = "Token SignatureException Login";
        }
        // JWT 토큰내에서 오류 발생 시
        else if(e instanceof JwtException) {
            resultMsg = "Token Parsing JwtException";
        }
        // 이외 JWT 토큰내에서 오류 발생
        else {
            resultMsg = "Other Token Error";
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
> ## 실행 결과
- 회원가입 후 DB에 저장된 이미지
<br> <img src="https://github.com/nineto6/BE-Login/blob/main/md_resource/be_resource_09.png">
- 로그인시 테스트용으로 응답한 비밀번호가 암호화 된 응답 이미지
<br> <img src="https://github.com/nineto6/BE-Login/blob/main/md_resource/be_resource_12.png">

<br/>
<hr/>

##### 20230603
> ## 계획
로그아웃 기능 구현
1. logout 요청시 Redis를 이용하여 Access-Token을 블랙리스트에 등록하게 한다.
    - Redis 만료 시간을 Access-Token의 남은 시간으로 지정한다.
2. 토큰 재발급을 못하게 막는다.
    - Redis에 등록한 Refresh-Token을 제거한다.
    - 그러면 이후에 재발급 요청시 Redis에 저장된 Refresh-Token이 없으므로 재발급이 불가능하다.
3. JwtAuthorizationFilter에서 로그아웃이 되어있는지 확인하는 검증을 작성한다.
    - key-value 형식으로된 Redis에서 Access-Token의 value 값이 없는지 확인한다.
    - 있으면 로그아웃이 된 Access-Token 이므로 에러 응답을 반환한다.
4. Access-Token이 유효해야 한다.
    - 로그아웃 요청시 Access-Token을 검증해야 한다. (JwtAuthorizationFilter 적용)

> ## RedisRepository 코드 추가
```Java
public interface RedisRepository extends CrudRepository<RefreshToken, Long> {
    RefreshToken findByRefreshToken(String refreshToken);
    RefreshToken findByUserId(String userId); // 추가
}
```

> ## RefreshToken 코드 추가
```Java
@Builder
@Getter
@AllArgsConstructor
@NoArgsConstructor
@RedisHash(value = "refresh", timeToLive = 259200) // 만료기간 3일로 지정
public class RefreshToken {
    @Id // null 로 저장될 경우 랜덤 값으로 설정됨
    private String id;

    private String ip;

    @Indexed // 보조 인덱스 적용 (로그아웃시 필요) // 추가 부분
    private String userId;

    @Indexed // Secondary indexes(보조 인덱스) 적용
    private String refreshToken;
}
```

> ## WebSecurityConfig 코드 변경
```Java
public class WebSecurityConfig {

    private final RedisRepository redisRepository;
    private final RedisTemplate<String, String> redisTemplate; // 추가

    // ... 기존 코드 생략
    /**
     * 1. 정적 자원(Resource)에 대해서 인증된 사용자가 정적 자원의 접근에 대해 ‘인가’에 대한 설정을 담당하는 메서드이다.
@ -172,7 +174,7 @@ public class WebSecurityConfig {
     */
    @Bean
    public JwtAuthorizationFilter jwtAuthorizationFilter() {
        return new JwtAuthorizationFilter(redisTemplate); // 변경
    }

    // ... 기존 코드 생략
}
```

> ## JwtAuthorizationFilter 코드 변경
```Java
@Slf4j
@RequiredArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final RedisTemplate<String, String> redisTemplate; // 추가

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 1. 토큰이 필요하지 않은 API URL 에 대해서 배열로 구성합니다.
        List<String> list = Arrays.asList(
                "/api/users/login",  // 로그인
                "/api/users/reissue", // 리프레쉬 토큰으로 재발급
                // "/api/test/generateToken", // 테스트 전용
                "/api/users/signup", // 회원가입
                "/api/users/duplicheck" // 회원가입 하위 사용 가능 ID 확인
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

                // [STEP3] 추출한 엑세스 토큰이 유효한지 여부를 체크합니다.
                if(token != null && TokenUtils.isValidAccessToken(token)) {
                    
                    // ------------ 변경 부분 ------------
                    
                    // [STEP 3-1] Redis 에 해당 Access-Token 로그아웃 확인
                    String isLogout = redisTemplate.opsForValue().get(token);

                    // 로그아웃이 되어 있지 않은 경우 해당 토큰은 정상적으로 작동
                    if(ObjectUtils.isEmpty(isLogout)){
                        // [STEP4] 토큰을 기반으로 사용자 아이디를 반환 받는 메서드
                        String userId = TokenUtils.getUserIdFormAccessToken(token);
                        log.debug("[+] userId Check: {}", userId);

                        // [STEP5] 사용자 아이디가 존재하는지 여부 체크
                        if(userId != null && !userId.equalsIgnoreCase("")) {
                            filterChain.doFilter(request, response);
                        } else {
                            // 사용자 아이디가 존재 하지 않을 경우
                            throw new BusinessExceptionHandler("Token isn't userId", ErrorCode.BUSINESS_EXCEPTION_ERROR);
                        }
                    } else {
                        // 현재 토큰이 로그아웃 되어 있는 경우
                        throw new BusinessExceptionHandler("Token is logged out", ErrorCode.BUSINESS_EXCEPTION_ERROR);
                    }
                    
                    // ------------ 변경 부분 ------------

                } else {
                    // 토큰이 유효하지 않은 경우
                    throw new BusinessExceptionHandler("Token is invalid", ErrorCode.BUSINESS_EXCEPTION_ERROR);
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

    // ... 기존 코드 생략
```

> ## TokenUtils 코드 추가
```Java
@Slf4j
@Component
public class TokenUtils {

    // ... 기존 코드 생략

    /**
     * 엑세스 토큰을 기반으로 만료 기간을 반환받는 메서드 (만료 시간 - 현재 시간 = 남은 시간(ms))
     * @param token
     * @return Long : Expiration
     */
    public static Long getExpirationFormAccessToken(String token) {
        Claims claims = getAccessTokenToClaimsFormToken(token);
        Date expiration = claims.getExpiration();
        return expiration.getTime() - System.currentTimeMillis();
    }
}
```
> ## UserController 코드 추가
```Java
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/users")
@Slf4j
public class UserController {
    
    // ... 기존 코드 생략

    /**
     * Access-Token 으로부터 로그아웃 (블랙리스트 저장)
     * @param request (Authorization : BEARER Access-Token)
     * @return ResponseEntity
     */
    @GetMapping("/logout")
    public ResponseEntity<ApiResponse> logout(HttpServletRequest request) {
        // 1. Request 에서 Header 추출
        String header = request.getHeader(AuthConstants.AUTH_HEADER);

        // 2. Header 에서 JWT Access Token 추출
        String token = TokenUtils.getTokenFormHeader(header);

        // 3. validateToken 메서드로 토큰 유효성 검사 (JwtAuthorizationFilter 인증 하기 때문에 필요 없다.)

        // Access Token 에서 user ID 값을 가져온다
        String userId = TokenUtils.getUserIdFormAccessToken(token);

        // Redis 에서 해당  user ID 로 저장된 Refresh Token 이 있는지 여부를 확인 후에 있을 경우 삭제를 한다.
        // (재발급을 불가능하게 만든다)
        RefreshToken refreshToken = refreshTokenRedisRepository.findByUserId(userId);
        if (refreshToken != null) {
            // refreshToken 이 있을 경우
            refreshTokenRedisRepository.delete(refreshToken);

            // 해당 Access Token 유효시간을 가지고 와서 블랙 리스트에 저장하기 
            // (Redis 유효기간을 Access-Token 만료 기간으로 설정)
            Long expiration = TokenUtils.getExpirationFormAccessToken(token);
            redisTemplate.opsForValue().set(token, "logout", expiration, TimeUnit.MILLISECONDS);

            
            // 성공
            ApiResponse ar = ApiResponse.builder()
                    .result("Logout Success") // 로그아웃 성공
                    .resultCode(SuccessCode.UPDATE_SUCCESS.getStatus())
                    .resultMsg(SuccessCode.UPDATE_SUCCESS.getMessage())
                    .build();
            return new ResponseEntity<>(ar, HttpStatus.OK);
        }

        ApiResponse ar = ApiResponse.builder()
                .result("Logout already requested") // 이미 요청된 로그아웃
                .resultCode(ErrorCode.BUSINESS_EXCEPTION_ERROR.getStatus())
                .resultMsg(ErrorCode.BUSINESS_EXCEPTION_ERROR.getMessage())
                .build();
        return new ResponseEntity<>(ar, HttpStatus.OK);
    }
}
```
> ## 실행 결과
- 로그아웃 성공 응답 이미지
<br> <img src="https://github.com/nineto6/BE-Login/blob/main/md_resource/be_resource_14.png">
- 로그아웃이 되어있는데, 인증이 필요한 URL에 요청시 에러 응답 이미지
<br> <img src="https://github.com/nineto6/BE-Login/blob/main/md_resource/be_resource_10.png">

<br/>
<hr/>

##### 20230630
> ## 계획
- 현재까지 권한 부분에 대해서 anonymous(익명 사용자)로 처리 되었지만 USER, ADMIN 권한을 추가하려고 한다.
- JwtAuthorizationFilter 한 클래스에서 Exception 응답 기능과 검증 부분을 맡아서 진행하게 되었는데, 401 (Unauthorized) 핸들러, 403 (Forbidden) 핸들러 클래스를 만들어서 역할을 분담하려고 한다.
- JwtAuthrizationFilter에서는 검증 부분만 진행하고 성공시 SecurityContext에 Authentication 객체를 넣으려고 한다.
- 한 사용자에게 복수의 권한을 가질 수 있게 한다. 예를 들어 권한이 ADMIN 일 때 USER 접근을 가능하게 해야하는 코드를 줄이려고 한다.
- USER 테이블의 1:N 관계인 USER_AUTHORITY 테이블을 생성하여 권한에 대한 부분을 넣고, UserDto 조회시 MyBatis의 ResultMap을 이용하여 USER 테이블을 조회 후 USER_AUTHORITY 테이블에서 userId에 맞는 권한을 List로 조회하게 하여 UserDto를 한번에 조회하려고 한다.
- /test/user은 USER 권한을 갖고 있어야지 접근할 수 있다.
- /test/admin은 ADMIN 권한을 갖고 있어야지 접근할 수 있다.
- AccessToken과 RefreshToken의 Subject 및 Claims 구성을 각각 다르게 변경한다.