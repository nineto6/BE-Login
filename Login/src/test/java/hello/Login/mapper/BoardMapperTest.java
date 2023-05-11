package hello.Login.mapper;

import hello.Login.model.BoardDto;
import hello.Login.model.UserDto;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import static org.assertj.core.api.Assertions.*;


@SpringBootTest
@Transactional
@Slf4j
class BoardMapperTest {
    @Autowired BoardMapper boardMapper;

    @Test
    @DisplayName("게시글 저장 테스트")
    void save() {
        // given

        BoardDto boardDto = BoardDto.builder()
                .userNm("홍길동")
                .boardTitle("안녕하세요")
                .boardContent("안녕하세요 첫 게시글입니다.")
                .build();

        // when
        boardMapper.save(boardDto);

        //then
        List<BoardDto> list = boardMapper.findAll();
        assertThat(list.get(0).getBoardSq()).isEqualTo(boardDto.getBoardSq());
        assertThat(list.get(0).getUserNm()).isEqualTo("홍길동");
        assertThat(list.get(0).getBoardTitle()).isEqualTo("안녕하세요");
        assertThat(list.get(0).getBoardContent()).isEqualTo("안녕하세요 첫 게시글입니다.");
    }

    @Test
    @DisplayName("게시글 모두 조회 테스트")
    void findAll() {
        UserDto user = UserDto.builder().build();
        // given
        BoardDto boardDto1 = BoardDto.builder()
                .userNm("홍길동")
                .boardTitle("안녕하세요")
                .boardContent("안녕하세요 첫번 째 게시글입니다.")
                .build();
        BoardDto boardDto2 = BoardDto.builder()
                .userNm("길동이")
                .boardTitle("안녕")
                .boardContent("안녕하세요 두번 째 게시글입니다.")
                .build();

        boardMapper.save(boardDto1);
        boardMapper.save(boardDto2);

        // when
        List<BoardDto> listBoard = boardMapper.findAll();

        // then
        assertThat(listBoard.size()).isEqualTo(2);
    }
}