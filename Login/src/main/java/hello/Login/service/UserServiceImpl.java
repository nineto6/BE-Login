package hello.Login.service;

import hello.Login.common.codes.ErrorCode;
import hello.Login.config.exception.BusinessExceptionHandler;
import hello.Login.mapper.UserMapper;
import hello.Login.model.UserDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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

    @Override
    @Transactional
    public void signUp(UserDto userDto) {
        Optional<UserDto> selectedUserDto = userMapper.login(userDto);
        if(selectedUserDto.isEmpty()) {
            userMapper.save(userDto);
            return;
        }
        throw new BusinessExceptionHandler(ErrorCode.INSERT_ERROR.getMessage(), ErrorCode.INSERT_ERROR);
    }
}
