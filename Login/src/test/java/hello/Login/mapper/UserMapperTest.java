package hello.Login.mapper;

import hello.Login.model.AuthorityDto;
import hello.Login.model.codes.Role;
import hello.Login.model.UserDto;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;

@SpringBootTest
@Transactional
@Slf4j
class UserMapperTest {

    @Autowired UserMapper userMapper;

    @Test
    @DisplayName("유저 저장 테스트")
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
        Optional<UserDto> login = userMapper.findByUserId("hello123");

        log.info("login is empty = {}", login.isEmpty());
        assertThat(login.isEmpty()).isFalse();
    }

    @Test
    @DisplayName("권한 저장 2개 테스트")
    void insertListOfAuthority() {
        // given
        UserDto user = UserDto.builder()
                .userId("hello123")
                .userPw("123123")
                .userNm("헬로")
                .userSt("X")
                .build();

        userMapper.save(user);

        ArrayList<AuthorityDto> auth = new ArrayList<>();
        auth.add(AuthorityDto.builder()
                .userId("hello123")
                .userSq(user.getUserSq())
                .userAuthority(Role.USER.getAuth()).build());

        auth.add(AuthorityDto.builder()
                .userId("hello123")
                .userSq(user.getUserSq())
                .userAuthority(Role.ADMIN.getAuth()).build());

        // when
        userMapper.insertAuthority(auth);

        // then userId 로 조회 후 권한 존재 유무 확인
        Optional<UserDto> login = userMapper.findByUserId("hello123");
        List<String> userRoles = login.get().getUserRoles();

        assertThat(userRoles.size()).isEqualTo(2);
        assertThat(userRoles.contains(Role.USER.getAuth())).isTrue();
        assertThat(userRoles.contains(Role.ADMIN.getAuth())).isTrue();
    }
}