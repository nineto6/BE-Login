package hello.Login.service;

import hello.Login.common.codes.ErrorCode;
import hello.Login.config.exception.BusinessExceptionHandler;
import hello.Login.mapper.UserMapper;
import hello.Login.model.AuthorityDto;
import hello.Login.model.UserDto;
import hello.Login.model.codes.Role;
import hello.Login.model.codes.Account;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.Optional;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserServiceImpl implements UserService{

    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;

    /**
     * 로그인 구현체
     * @param String UserId
     * @return Optional<UserDto>
     */
    @Override
    @Transactional(readOnly = true)
    public Optional<UserDto> findByUserId(String userId) {
        return userMapper.findByUserId(userId);
    }

    @Override
    @Transactional
    public void signUp(UserDto userDto) {
        Optional<UserDto> selectedUserDto = userMapper.findByUserId(userDto.getUserId()); // findByUserId

        if(selectedUserDto.isEmpty()) {
            UserDto saveUserDto = UserDto.builder()
                    .userId(userDto.getUserId())
                    .userPw(passwordEncoder.encode(userDto.getUserPw())) // 패스워드 암호화
                    .userNm(userDto.getUserNm())
                    .userSt(Account.UNSLEEPER.getState())
                    .build();
            // 유저 저장
            userMapper.save(saveUserDto);

            // 유저 권한 부여
            userMapper.insertAuthority(Collections.singletonList(AuthorityDto.builder()
                    .userSq(saveUserDto.getUserSq())
                    .userId(saveUserDto.getUserId())
                    .userAuthority(Role.USER.getAuth())
                    .build()));
            return;
        }

        throw new BusinessExceptionHandler(ErrorCode.INSERT_ERROR.getMessage(), ErrorCode.INSERT_ERROR);
    }
}

