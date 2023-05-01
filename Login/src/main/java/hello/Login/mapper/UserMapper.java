package hello.Login.mapper;

import hello.Login.model.UserDto;
import org.apache.ibatis.annotations.Mapper;

import java.util.Optional;

@Mapper
public interface UserMapper {
    Optional<UserDto> login(UserDto userDto);
}
