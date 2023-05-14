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

> ## CustomAuthSuccessHandler 작성

> ## CustomAuthFailureHandler 작성

> ## CustomAuthenticationProvider 작성

> ## UserDto 작성

> ## UserDetailsDto 작성

> ## UserMapper 작성

> ## WebSecurityConfig 작성

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
