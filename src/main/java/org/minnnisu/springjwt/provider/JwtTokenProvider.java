package org.minnnisu.springjwt.provider;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.minnnisu.springjwt.constant.ErrorCode;
import org.minnnisu.springjwt.domain.Users;
import org.minnnisu.springjwt.dto.TokenDto;
import org.minnnisu.springjwt.exception.CustomErrorException;
import org.minnnisu.springjwt.exception.UserNotFoundException;
import org.minnnisu.springjwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Slf4j
@Component
public class JwtTokenProvider {
    private final Key key;
    private final UserRepository userRepository;

    public JwtTokenProvider(@Value("${jwt.secret}") String secretKey, UserRepository userRepository) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.userRepository = userRepository;
    }

    // 유저 정보를 가지고 AccessToken, RefreshToken 을 생성하는 메서드
    public TokenDto generateToken(Authentication authentication) {
        Claims claims = Jwts.claims().setSubject(authentication.getName()); // subject

        long now = (new Date()).getTime();
        // Access Token 생성
        // 숫자 86400000은 토큰의 유효기간으로 1일을 나타냅니다. 보통 토큰은 30분 정도로 생성하는데 테스트를 위해 1일로 설정했습니다.
        // 1일: 24*60*60*1000 = 86400000
        Date accessTokenExpiresIn = new Date(now + 60000);
        String accessToken = Jwts.builder()
                .setClaims(claims) //정보 저장
                .setIssuedAt(new Date()) //토큰 발행 시간 정보
                .setExpiration(accessTokenExpiresIn)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        // Refresh Token 생성
        String refreshToken = Jwts.builder()
                .setExpiration(new Date(now + 86400000))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        return TokenDto.builder()
                .grantType("Bearer")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    // JWT 토큰을 복호화하여 토큰에 들어있는 정보를 꺼내는 메서드
    public Authentication getAuthentication(String accessToken) {
        // 토큰 복호화
        // Claim: 사용자에 대한 프로퍼티나 속성
        Claims claims = parseClaims(accessToken);

        if (claims.get("sub") == null) {
            throw new RuntimeException("권한 정보가 없는 토큰입니다.");
        }

        String username = claims.get("sub").toString();
        Users users = userRepository.findByUsername(username).orElseThrow(UserNotFoundException::new);

        return new UsernamePasswordAuthenticationToken(users, "", users.getAuthorities());
    }

    // 토큰 정보를 검증하는 메서드
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException | UnsupportedJwtException e) {
            throw new CustomErrorException(ErrorCode.NotValidJwtError);
        } catch (ExpiredJwtException e) {
            throw new CustomErrorException(ErrorCode.ExpiredJwtError);
        } catch (IllegalArgumentException e) {
            throw new CustomErrorException(ErrorCode.IllegalArgumentError);
        }
    }

    private Claims parseClaims(String accessToken) {
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(accessToken).getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }
}
