package org.minnnisu.springjwt.provider;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.minnnisu.springjwt.constant.ErrorCode;
import org.minnnisu.springjwt.constant.TokenType;
import org.minnnisu.springjwt.domain.Users;
import org.minnnisu.springjwt.exception.CustomErrorException;
import org.minnnisu.springjwt.exception.UserNotFoundException;
import org.minnnisu.springjwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.Key;
import java.util.Date;

@Slf4j
@Component
public class JwtTokenProvider {
    private final Key key;
    private final UserRepository userRepository;

    @Value("${jwt.access.expiration}")
    private Long accessTokenExpirationPeriod;

    @Value("${jwt.refresh.expiration}")
    private Long refreshTokenExpirationPeriod;

    @Value("${jwt.access.header}")
    private String accessHeader;

    @Value("${jwt.refresh.header}")
    private String refreshHeader;


    public JwtTokenProvider(@Value("${jwt.secret}") String secretKey, UserRepository userRepository) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.userRepository = userRepository;
    }

    // 유저 정보를 가지고 AccessToken, RefreshToken 을 생성하는 메서드
    public String generateAccessToken(Authentication authentication) {
        Claims claims = Jwts.claims().setSubject(authentication.getName()); // subject
        Date now = new Date();

        return Jwts.builder()
                .setClaims(claims) //정보 저장
                .setIssuedAt(now) //토큰 발행 시간 정보
                .setExpiration(new Date(now.getTime() + accessTokenExpirationPeriod))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateRefreshToken() {
        Date now = new Date();

        // Refresh Token 생성
        return Jwts.builder()
                .setExpiration(new Date(now.getTime() + refreshTokenExpirationPeriod))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }


    public Authentication getAuthentication(String accessToken) {
        // 토큰 복호화
        // Claim: 사용자에 대한 프로퍼티나 속성
        Claims claims = parseClaims(accessToken);

        if (claims.get("sub") == null) {
            throw new CustomErrorException(ErrorCode.NotValidAccessTokenError);
        }

        String username = claims.get("sub").toString();
        Users users = userRepository.findByUsername(username).orElseThrow(() -> new CustomErrorException(ErrorCode.UserNotFoundError));

        return new UsernamePasswordAuthenticationToken(users, "", users.getAuthorities());
    }

    // 토큰 정보를 검증하는 메서드
    public void validateAccessToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException | UnsupportedJwtException e) {
            throw new CustomErrorException(ErrorCode.NotValidAccessTokenError);
        } catch (ExpiredJwtException e) {
            throw new CustomErrorException(ErrorCode.ExpiredAccessTokenError);
        } catch (IllegalArgumentException e) {
            throw new CustomErrorException(ErrorCode.IllegalArgumentError);
        }
    }

    public void validateRefreshToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException | UnsupportedJwtException e) {
            throw new CustomErrorException(ErrorCode.NotValidRefreshTokenError);
        } catch (ExpiredJwtException e) {
            throw new CustomErrorException(ErrorCode.ExpiredRefreshTokenError);
        } catch (IllegalArgumentException e) {
            throw new CustomErrorException(ErrorCode.IllegalArgumentError);
        }
    }


    public boolean isExpiredAccessToken(String accessToken){
        try{
            validateAccessToken(accessToken);
        }catch (CustomErrorException e){
            if(e.getErrorCode() == ErrorCode.ExpiredAccessTokenError){
                return true;
            }
            throw e;
        }
        return false;
    }



    private Claims parseClaims(String accessToken) {
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(accessToken).getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }

    public void responseAccessToken(HttpServletResponse response, String accessToken){
        response.setStatus(HttpStatus.OK.value());

        response.setHeader(accessHeader, accessToken);
    }

    public void responseAccessAndRefreshToken(HttpServletResponse response, String accessToken, String refreshToken){
        response.setStatus(HttpStatus.OK.value());

        response.setHeader(accessHeader, accessToken);
        response.setHeader(refreshHeader, refreshToken);
    }

    public String resolveToken(TokenType tokenType, HttpServletRequest request) {
        String bearerToken = "";

        if (tokenType == TokenType.ACCESS_TOKEN){
            bearerToken = request.getHeader("Authorization");
        }

        if (tokenType == TokenType.REFRESH_TOKEN){
            bearerToken = request.getHeader("Authorization-refresh");
        }

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer")) {
            return bearerToken.substring(7);
        }

        return null;
    }

    public String resolveToken(String value) {
        if (StringUtils.hasText(value) && value.startsWith("Bearer")) {
            return value.substring(7);
        }

        return null;
    }

    public String reIssueAccessToken(String accessToken) {
        Authentication authentication = getAuthentication(accessToken);
        Claims claims = Jwts.claims().setSubject(authentication.getName()); // subject
        Date now = new Date();

        return Jwts.builder()
                .setClaims(claims) //정보 저장
                .setIssuedAt(now) //토큰 발행 시간 정보
                .setExpiration(new Date(now.getTime() + accessTokenExpirationPeriod))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }
}
