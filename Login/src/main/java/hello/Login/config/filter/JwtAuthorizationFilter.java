package hello.Login.config.filter;

import hello.Login.common.codes.AuthConstants;
import hello.Login.common.codes.ErrorCode;
import hello.Login.common.utils.TokenUtils;
import hello.Login.config.exception.BusinessExceptionHandler;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.SignatureException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.json.simple.JSONObject;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.util.ObjectUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

/**
 * 지정한 URL 별 JWT 유효성 검증을 수행하며 직접적인 사용자 '인증'을 확인합니다.
 */
@Slf4j
@RequiredArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter {
    private final RedisTemplate<String, String> redisTemplate;
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

    /**
     * 토큰 관련 Exception 발생 시 예외 응답값 구성
     * @param e Exception
     * @return JSONObject
     */
    private JSONObject jsonResponseWrapper(Exception e) {
        String resultMsg = "";

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
