package hello.Login.model;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class AuthorityDto {
    private int userAuthSq;
    private int userSq;
    private String userId;
    private String userAuthority;

    @Builder
    public AuthorityDto(int userAuthSq, int userSq, String userId, String userAuthority) {
        this.userAuthSq = userAuthSq;
        this.userSq = userSq;
        this.userId = userId;
        this.userAuthority = userAuthority;
    }
}
