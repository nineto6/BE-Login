package hello.Login.controller;

import hello.Login.common.codes.AuthConstants;
import hello.Login.common.codes.ErrorCode;
import hello.Login.common.codes.SuccessCode;
import hello.Login.common.utils.NetUtils;
import hello.Login.config.JwtToken;
import hello.Login.common.utils.TokenUtils;
import hello.Login.config.redis.RedisRepository;
import hello.Login.config.redis.RefreshToken;
import hello.Login.controller.response.ApiResponse;
import hello.Login.model.UserDto;
import hello.Login.service.UserService;
import lombok.RequiredArgsConstructor;
import org.apache.el.parser.Token;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Optional;

@RestController
@RequestMapping("/api/reissue")
@RequiredArgsConstructor
public class AccountController {

    private final RedisRepository refreshTokenRedisRepository;
    private final UserService userService;

    @GetMapping
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
                                .result("Reissue Success")
                                .resultCode(SuccessCode.UPDATE_SUCCESS.getStatus())
                                .resultMsg(SuccessCode.UPDATE_SUCCESS.getMessage())
                                .build();

                        return new ResponseEntity<>(ar, HttpStatus.OK);
                    }
                }
            }
        }

        ApiResponse ar = ApiResponse.builder()
                .result("It cannot be reissued.")
                .resultCode(ErrorCode.BUSINESS_EXCEPTION_ERROR.getStatus())
                .resultMsg(ErrorCode.BUSINESS_EXCEPTION_ERROR.getMessage())
                .build();
        return new ResponseEntity<>(ar, HttpStatus.OK);
    }
}
