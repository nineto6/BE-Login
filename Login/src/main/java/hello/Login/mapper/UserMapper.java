package hello.Login.mapper;

import hello.Login.model.AuthorityDto;
import hello.Login.model.UserDto;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Optional;

@Mapper
public interface UserMapper {
    void save(UserDto userDto);
    void insertAuthority(List<AuthorityDto> authorities);
    Optional<UserDto> findByUserId(String userId);
}
