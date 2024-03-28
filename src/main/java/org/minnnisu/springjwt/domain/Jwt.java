package org.minnnisu.springjwt.domain;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

@Getter
@AllArgsConstructor
@RedisHash(value = "people")
public class Jwt {
    @Id
    private String refreshToken;
    private String accessToken;
}
