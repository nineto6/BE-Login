package hello.Login.service;

import hello.Login.mapper.UserMapper;
import hello.Login.model.UserDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserServiceImpl implements UserService{

    private final UserMapper userMapper;

    /**
     * 로그인 구현체
     * @param userDto UserDto
     * @return Optional<UserDto>
     */
    @Override
    public Optional<UserDto> login(UserDto userDto) {
        return userMapper.login(userDto);
    }
}
