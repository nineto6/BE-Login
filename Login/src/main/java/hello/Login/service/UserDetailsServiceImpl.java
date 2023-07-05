package hello.Login.service;

import hello.Login.model.UserDetailsDto;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserService userService;

    public UserDetailsServiceImpl(UserService us) {
        this.userService = us;
    }

    @Transactional(readOnly = true)
    @Override
    public UserDetails loadUserByUsername(String userId) throws UsernameNotFoundException {
        // 사용자 정보가 존재하지 않는 경우 예외 처리
        if(userId == null || userId.equals("")) {
            return userService.findByUserId(userId)
                    .map(u -> new UserDetailsDto(u, u.getUserRoles()))
                    .orElseThrow(() -> new AuthenticationServiceException(userId));
        }

        // 비밀번호가 맞지 않는 경우 예외 처리
        else {
            return userService.findByUserId(userId)
                    .map(u -> new UserDetailsDto(u, u.getUserRoles()))
                    .orElseThrow(() -> new BadCredentialsException(userId));
        }
    }
}
