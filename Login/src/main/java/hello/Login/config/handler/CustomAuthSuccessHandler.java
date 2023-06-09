package hello.Login.config.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import hello.Login.common.codes.AuthConstants;
import hello.Login.common.utils.NetUtils;
import hello.Login.config.JwtToken;
import hello.Login.common.utils.TokenUtils;
import hello.Login.config.redis.RedisRepository;
import hello.Login.config.redis.RefreshToken;
import hello.Login.model.UserDetailsDto;
import hello.Login.model.UserDto;
import hello.Login.model.codes.Account;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;

/**
 * 사용자의 ‘인증’에 대해 성공하였을 경우 수행되는 Handler 로 성공에 대한 사용자에게 반환값을 구성하여 전달합니다
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
public class CustomAuthSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private final RedisRepository refreshTokenRedisRepository;

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
        // [STEP3-1] 사용자의 상태가 '휴면 상태' 인 경우 응답 값으로 전달 할 데이터
        if(userDto.getUserSt().equals(Account.SLEEPER.getState())) {
            responseMap.put("userInfo", userVoObj);
            responseMap.put("resultCode", 9001);
            responseMap.put("token", null);
            responseMap.put("failMsg", "휴먼 계정입니다.");
            jsonObject = new JSONObject(responseMap);
        }

        // [STEP3-2] 사용자의 상태가 '휴면 상태'가 아닌 경우 응답 값으로 전달할 데이터
        else {
            // 1. 일반 계정일 경우 데이터 세팅
            responseMap.put("userInfo", userVoObj);
            responseMap.put("resultCode", 200);
            responseMap.put("failMsg", null);
            jsonObject = new JSONObject(responseMap);

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
        }

        // [STEP4] 구성한 응답 값을 전달합니다.
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json");
        PrintWriter printWriter = response.getWriter();
        printWriter.print(jsonObject); // 최종 저장된 '사용자 정보', '사이트 정보' Front 전달
        printWriter.flush();
        printWriter.close();
    }
}
