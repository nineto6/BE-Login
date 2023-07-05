package hello.Login.service;

import hello.Login.model.UserDto;

import java.util.Optional;

public interface UserService {
    Optional<UserDto> findByUserId(String userDto);
    void signUp(UserDto userDto);
}
