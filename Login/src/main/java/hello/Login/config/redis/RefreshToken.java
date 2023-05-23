package hello.Login.config.redis;

import hello.Login.model.UserDto;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.index.Indexed;

@Builder
@Getter
@AllArgsConstructor
@NoArgsConstructor
@RedisHash(value = "refresh", timeToLive = 1209600)
public class RefreshToken {
    @Id // null 로 저장될 경우 랜덤 값으로 설정됨
    private String id;

    private String ip;

    private UserDto userDto;

    @Indexed // Secondary indexes(보조 인덱스) 적용
    private String refreshToken;
}
