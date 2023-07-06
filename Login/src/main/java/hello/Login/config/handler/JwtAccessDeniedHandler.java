package hello.Login.config.handler;

import hello.Login.common.codes.ErrorCode;
import lombok.extern.slf4j.Slf4j;
import org.json.simple.JSONObject;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;

/**
 * 403 Forbidden Exception 처리를 위한 클래스
 * 공통적인 응답을 위한 ErrorResponse
 */
@Slf4j
public class JwtAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json");
        PrintWriter printWriter = response.getWriter();

        JSONObject jsonObject = jsonResponseWrapper(accessDeniedException);

        printWriter.print(jsonObject);
        printWriter.close();
    }

    private JSONObject jsonResponseWrapper (Exception e) {
        log.error("403 Forbidden 에러 : ", e);

        HashMap<String, Object> jsonMap = new HashMap<>();
        jsonMap.put("status", ErrorCode.FORBIDDEN.getStatus());
        jsonMap.put("code", ErrorCode.FORBIDDEN.getDivisionCode());
        jsonMap.put("message", ErrorCode.FORBIDDEN.getMessage());
        jsonMap.put("reason", "Forbidden"); // reason 을 내보내지 않기 위함 (exception 보안 문제)
        return new JSONObject(jsonMap);
    }
}
