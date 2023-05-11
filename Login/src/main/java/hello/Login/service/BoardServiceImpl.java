package hello.Login.service;

import hello.Login.mapper.BoardMapper;
import hello.Login.model.BoardDto;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@AllArgsConstructor
public class BoardServiceImpl implements BoardService{
    private final BoardMapper boardMapper;

    @Override
    @Transactional
    public BoardDto create(BoardDto boardDto) {
        boardMapper.save(boardDto);
        return boardDto;
    }

    @Override
    @Transactional(readOnly = true)
    public List<BoardDto> findList() {
        return boardMapper.findAll();
    }
}
