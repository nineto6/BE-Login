package hello.Login.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import hello.Login.common.codes.AuthConstants;
import hello.Login.common.codes.SuccessCode;
import hello.Login.common.utils.TokenUtils;
import hello.Login.controller.response.ApiResponse;
import hello.Login.controller.response.ObjectApiResponse;
import hello.Login.model.BoardDto;
import hello.Login.service.BoardService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

@RestController
@RequestMapping("/api/board")
@AllArgsConstructor
@Slf4j
public class BoardController {
    private final BoardService boardService;

    @PostMapping
    public ResponseEntity<ApiResponse> createBoard(@RequestBody BoardDto boardDto, HttpServletRequest request) {
        String userNm = TokenUtils.getUserNmFormAccessToken(
                TokenUtils.getTokenFormHeader(
                        request.getHeader(AuthConstants.AUTH_HEADER
                        )));

        BoardDto board = BoardDto.builder()
                .userNm(userNm)
                .boardTitle(boardDto.getBoardTitle())
                .boardContent(boardDto.getBoardContent())
                .build();

        boardService.create(board);

        ApiResponse ar = ApiResponse.builder()
                .result(null)
                .resultCode(SuccessCode.INSERT_SUCCESS.getStatus())
                .resultMsg(SuccessCode.INSERT_SUCCESS.getMessage())
                .build();

        return new ResponseEntity<>(ar, HttpStatus.OK);
    }

    @GetMapping
    public ResponseEntity<ObjectApiResponse> findAllBoard() {

        List<BoardDto> list = boardService.findList();

        ObjectApiResponse ar = ObjectApiResponse.builder()
                .result(list)
                .resultCode(SuccessCode.SELECT_SUCCESS.getStatus())
                .resultMsg(SuccessCode.SELECT_SUCCESS.getMessage())
                .build();

        return new ResponseEntity<>(ar, HttpStatus.OK);
    }
}
