package hello.Login.mapper;

import hello.Login.model.BoardDto;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface BoardMapper {
    void save(BoardDto boardDto);
    List<BoardDto> findAll();
}
