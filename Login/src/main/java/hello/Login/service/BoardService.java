package hello.Login.service;

import hello.Login.model.BoardDto;

import java.util.List;

public interface BoardService {
    BoardDto create(BoardDto boardDto);
    List<BoardDto> findList();
}
