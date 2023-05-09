package hello.Login.mapper;

import hello.Login.model.UserDto;
import lombok.extern.slf4j.Slf4j;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@Transactional
@Slf4j
class UserMapperTest {

    @Autowired UserMapper userMapper;

    @Test
    void save() {
        //given
        UserDto user = UserDto.builder()
                .userId("hello123")
                .userPw("123123")
                .userNm("헬로")
                .userSt("X")
                .build();

        // when
        userMapper.save(user);
        log.info("userSq = {}", user.getUserSq());

        // then
        Optional<UserDto> login = userMapper.login(user);

        log.info("login is empty = {}", login.isEmpty());
        Assertions.assertThat(login.isEmpty()).isFalse();
    }
}