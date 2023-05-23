package hello.Login.common.utils;

import hello.Login.config.JwtToken;
import hello.Login.model.UserDto;
import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * JWT 관련된 토큰 Util
 */
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
