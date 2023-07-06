package hello.Login.config.handler;

import hello.Login.common.codes.ErrorCode;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import lombok.extern.slf4j.Slf4j;
import org.json.simple.JSONObject;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.SignatureException;
import java.util.HashMap;

/**
 * 401 Unauthorized Exception 처리를 위한 클래스
 */
@Slf4j
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json");
        PrintWriter printWriter = response.getWriter();

        JSONObject jsonObject = jsonResponseWrapper(authException);

        printWriter.print(jsonObject);
        printWriter.close();
    }

    private JSONObject jsonResponseWrapper (Exception e) {
        String resultMsg = "";

        // 만료된 토큰만 resultMsg 에 적용 (프론트 검증시 필요(Refresh-Token 사용하기 위함))
        // JWT 토큰 만료 (사용)
        if(e instanceof ExpiredJwtException) {
            resultMsg = "Token Expired";
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
        jsonMap.put("status", ErrorCode.UNAUTHORIZED.getStatus());
        jsonMap.put("code", ErrorCode.UNAUTHORIZED.getDivisionCode());
        jsonMap.put("message", ErrorCode.UNAUTHORIZED.getMessage());
        jsonMap.put("reason", resultMsg); // reason 을 내보내지 않기 위함 (exception 보안 문제)
        JSONObject jsonObject = new JSONObject(jsonMap);

        log.error(resultMsg, e);

        return jsonObject;
    }
}
