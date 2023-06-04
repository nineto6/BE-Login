package hello.Login.config.redis;

import org.springframework.data.repository.CrudRepository;

/**
 * CrudRepository 를 상속하는 CustomInterface 를 생성
 * redisRepository 방식은 CrudRepository 를 상속받은 인터페이스가 사용되기 때문에 Spring Data JPA 에서
 * JpaRepository 를 사용하는 방식과 유사하다는 특징이 있다.
 */
public interface RedisRepository extends CrudRepository<RefreshToken, Long> {
    RefreshToken findByRefreshToken(String refreshToken);
    RefreshToken findByUserId(String userId);
}
