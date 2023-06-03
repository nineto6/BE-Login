package hello.Login.controller;

import hello.Login.common.codes.AuthConstants;
import hello.Login.common.codes.ErrorCode;
import hello.Login.common.codes.SuccessCode;
import hello.Login.common.utils.NetUtils;
import hello.Login.common.utils.TokenUtils;
import hello.Login.config.JwtToken;
import hello.Login.config.exception.BusinessExceptionHandler;
import hello.Login.config.redis.RedisRepository;
import hello.Login.config.redis.RefreshToken;
import hello.Login.controller.response.ApiResponse;
import hello.Login.model.UserDto;
import hello.Login.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.constraints.NotBlank;
import java.util.Optional;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/users")
@Slf4j
public class UserController {
    private final RedisRepository refreshTokenRedisRepository;

    private final RedisTemplate<String, String> redisTemplate;
    private final UserService userService;

    /**
     * UserId, UserPw, UserNm 을 받아서 회원가입 (JwtAuthorizationFilter 인증 X)
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
                .userSt("X") // 유저 상태
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
     * userId 값을 받아와서 사용 가능한 Id 체크 (가능 true, 불가능 false) (JwtAuthorizationFilter 인증 X)
     * @param userId
     * @return ResponseEntity
     */
    @GetMapping("/duplicheck")
    public ResponseEntity<ApiResponse> duplicateCheck(@RequestParam @NotBlank(message = "No spaces are allowed.") String userId) {
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
}
