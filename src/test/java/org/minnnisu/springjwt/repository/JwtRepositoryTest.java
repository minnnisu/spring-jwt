package org.minnnisu.springjwt.repository;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.minnnisu.springjwt.domain.Jwt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class JwtRepositoryTest {

    @Autowired
    private JwtRepository jwtRepository;

    private Jwt jwt;

    @BeforeEach
    void setUp() {
        jwt = new Jwt("P0001", "테스트_상품");
    }

    @AfterEach
    void teardown() {
        jwtRepository.deleteById(jwt.getAccessToken());
    }

    @Test
    @DisplayName("Redis 에 데이터를 저장하면 정상적으로 조회되어야 한다")
    void redis_save_test() {
        // given
        jwtRepository.save(jwt);

        // when
        Jwt persistJwt = jwtRepository.findById(jwt.getRefreshToken())
                .orElseThrow(RuntimeException::new);

//        // then
//        assertThat(persistJwt()).isEqualTo(product.getId());
//        assertThat(persistJwt.getName()).isEqualTo(product.getName());
//        assertThat(persistJwt.getPrice()).isEqualTo(product.getPrice());
    }
}