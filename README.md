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

> ## Dependencies 추가
- implementation 'com.googlecode.json-simple:json-simple:1.1.1' // simple-json 추가

> ## CustomAuthenticationFilter 작성
```Java
/**
 * 아이디와 비밀번호 기반의 데이터를 Form 데이터로 전송을 받아 '인증'을 담당하는 필터입니다.
 */
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
```Java
/**
 * 사용자의 ‘인증’에 대해 성공하였을 경우 수행되는 Handler 로 성공에 대한 사용자에게 반환값을 구성하여 전달합니다
 */
@Slf4j
@Configuration
public class CustomAuthSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

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
```Java
/**
 * 사용자의 ‘인증’에 대해 실패하였을 경우 수행되는 Handler 로 실패에 대한 사용자에게 반환값을 구성하여 전달합니다.
 */
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
```Java
/**
 * 전달받은 사용자의 아이디와 비밀번호를 기반으로 비즈니스 로직을 처리하여 사용자의 ‘인증’에 대해서 검증을 수행하는 클래스입니다.
 * CustomAuthenticationFilter 로 부터 생성한 토큰을 통하여 ‘UserDetailsService’를 통해 데이터베이스 내에서 정보를 조회합니다.
 */
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

> ## UserMapper 작성
```Java
@Mapper
public interface UserMapper {
    void save(UserDto userDto);
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

    <!-- 회원가입 -->
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

> ## WebSecurityConfig 작성
```Java
/**
 * Spring Security 환경 설정을 구성하기 위한 클래스입니다.
 * 웹 서비스가 로드 될때 Spring Container 의해 관리가 되는 클래스이며 사용자에 대한 ‘인증’과 ‘인가’에 대한 구성을 Bean 메서드로 주입을 한다.
 */
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
                //.addFilterBefore(jwtAuthorizationFilter(), BasicAuthenticationFilter.class)

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
- 프론트와 요청을 주고받을 수 있게 WebSecuritConfig에 설정 및 Bean 등록
```Java
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

> ## SuccessCode

> ## BusinessExceptionHandler

> ## ApiResponse
<br/>
<hr/>

##### 20230504
> ## Dependencies 추가
- implementation 'io.jsonwebtoken:jjwt:0.9.1' // jwt 

> ## AuthConstants 추가

> ## TokenUtils 추가

> ## JwtAuthorizationFilter 추가
<br/>
<hr/>

##### 20230506
> ## 인증서 없이 개발 전용 SSL 인증 추가
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

> ## UserMapperTest 작성
<br/>
<hr/>

##### 20230510
> ## TokenUtils의 토큰을 기반으로 사용자 닉네임을 반환받는 메서드 작성

> ## WebConfig의 CorsConfiguration에서 addExposedHeader("Authorization") 추가

> ## TestController 작성

> ## .../api/test/generateToken URL에 Front에서 Back 서버로 요청 및 응답 확인
- HTTP Body JSON 내용 이미지
<img src="https://github.com/nineto6/BE-Login/blob/main/md_resource/fe_resource_02.png">
<br/>
<hr/>

##### 20230511
> ## BoardDto 작성

> ## BoardMapper 작성

> ## BoardMapperTest 작성

> ## BoardService 인터페이스 작성

> ## BoardService의 구현체 BoardServiceImpl 작성
<br/>
<hr/>

##### 20230512
> ## BoardController REST 컨트롤러 작성

> ## ObjectApiResponse 작성
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
> ## JwtAuthorizationFilter 코드 추가
> ## 테스트
