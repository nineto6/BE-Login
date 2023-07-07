package hello.Login.controller;

import hello.Login.common.codes.AuthConstants;
import hello.Login.common.codes.SuccessCode;
import hello.Login.common.utils.TokenUtils;
import hello.Login.config.JwtToken;
import hello.Login.controller.response.ApiResponse;
import hello.Login.model.UserDto;
import io.swagger.v3.oas.annotations.Operation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/test")
public class TestController {
    @PostMapping("/generateToken")
    @Operation(summary = "토큰 발급", description = "사용자 정보를 기반으로 JWT 를 발급하는 API")
    public ResponseEntity<ApiResponse> selectCodeList(@RequestBody UserDto userDto) {
        // 토큰 생성
        JwtToken jwtToken = TokenUtils.generateJwtToken(userDto);

        List<String> list = new ArrayList<>();
        list.add("Access-Token : " + jwtToken.getAccessToken());
        list.add("Refresh-Token : " + jwtToken.getRefreshToken());

        ApiResponse ar = ApiResponse.builder()
                // BEARER {토큰} 형태로 반환을 해줍니다.
                .result(list)
                .resultCode(SuccessCode.SELECT_SUCCESS.getStatus())
                .resultMsg(SuccessCode.SELECT_SUCCESS.getMessage())
                .build();

        return new ResponseEntity<>(ar, HttpStatus.OK);
    }

    @GetMapping("/user")
    public ResponseEntity<ApiResponse> user() {
        ApiResponse ar = ApiResponse.builder()
                .result("들어와짐")
                .resultCode(200)
                .resultMsg("하이 유저")
                .build();
        return ResponseEntity.ok().body(ar);
    }

    @GetMapping("/admin")
    public ResponseEntity<ApiResponse> admin() {
        ApiResponse ar = ApiResponse.builder()
                .result("들어와짐")
                .resultCode(200)
                .resultMsg("하이 어드민")
                .build();
        return ResponseEntity.ok().body(ar);
    }
}
