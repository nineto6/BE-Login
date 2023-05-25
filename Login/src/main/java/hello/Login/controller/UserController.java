package hello.Login.controller;

import hello.Login.common.codes.SuccessCode;
import hello.Login.config.exception.BusinessExceptionHandler;
import hello.Login.controller.response.ApiResponse;
import hello.Login.model.UserDto;
import hello.Login.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.constraints.NotBlank;
import java.util.Optional;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/user")
@Slf4j
public class UserController {
    private final UserService userService;

    /**
     * UserId, UserPw, UserNm 을 받아서 회원가입
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
     * userId 값을 받아와서 사용 가능한 Id 체크 (가능 true, 불가능 false)
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
}
