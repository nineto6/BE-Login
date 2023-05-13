# 🛠️NINETO6 사이드프로젝트 만들기

## 시작하기 전에...

ErrorCode, Security, JWT 등을 참고한 사이트 출처 [Contributor9 블로그](https://adjh54.tistory.com)
<br/>
<p>
<img src="https://img.shields.io/badge/Java-007396.svg?&style=for-the-badge&logo=Java&logoColor=white"/>
<img src="https://img.shields.io/badge/Spring%20Boot-6DB33F.svg?&style=for-the-badge&logo=SpringBoot&logoColor=white"/>
<img src="https://img.shields.io/badge/Spring-6DB33F.svg?&style=for-the-badge&logo=Spring&logoColor=white"/>
<img src="https://img.shields.io/badge/Spring%20Security-6DB33F.svg?&style=for-the-badge&logo=Spring&logoColor=white">
<img src="https://img.shields.io/badge/MyBatis-000000.svg?&style=for-the-badge&logoColor=white">
<p/>

- 현재 `Front-End` 와 `Back-end` 는 다른 환경에서 개발하고 있음
- 초기 Dependencies : Spring Web, Spring Security, Mybatis, Lombok, H2 Database
<br/>
<hr/>

###### 20230501
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

> ## Spring Security 설정
- ### Handler 추가
- ### Filter 추가
- ### Provider 생성
- ### WebSecurityConfig 생성 및 설정

> ## Use Dto, UserDetailsDto 추가

> ## Mybatis 생성 (UserMapper.java, UserMapper.xml)

> ## Simple-JSON 디펜던시 추가
<br/>
<hr/>

##### 20230502

> ## Spring CORS 문제 해결 및 설정 코드 작성
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
<br/>
<hr/>

##### 20230503
> ## ErrorCode

> ## SuccessCode

> ## BusinessExceptionHandler

> ## ApiResponse

> ## Build.gradle에 Dependencies 추가
- implementation 'org.springdoc:springdoc-openapi-ui:1.6.12' // Swagger 추가
- implementation 'org.glassfish.jaxb:jaxb-runtime:2.3.2' // DataTypeConverter 추가
<br/>
<hr/>

##### 20230504
> ## JWT 토큰 관련 코드 작성
- JWT 관련된 토큰 Util 생성
- URL 별 JWT 검증 수행 사용자 인증기 생성
- JWT 관련된 상수로 사용 되는 파일 생성
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
> ## UserMapper Insert 문 추가 (회원가입)

> ## UserMapperTest 작성
<br/>
<hr/>

##### 20230510
> ## TokenUtils의 토큰을 기반으로 사용자 닉네임을 반환받는 메서드 작성

> ## WebConfig의 CorsConfiguration에서 addExposedHeader("Authorization") 추가
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
