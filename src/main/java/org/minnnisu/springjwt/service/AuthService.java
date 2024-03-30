package org.minnnisu.springjwt.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.minnnisu.springjwt.constant.ErrorCode;
import org.minnnisu.springjwt.domain.Users;
import org.minnnisu.springjwt.dto.ReIssueTokenDto;
import org.minnnisu.springjwt.dto.SignupDto;
import org.minnnisu.springjwt.exception.CustomErrorException;
import org.minnnisu.springjwt.provider.JwtTokenProvider;
import org.minnnisu.springjwt.repository.UserRepository;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {
    private final RedisTemplate<String, String> redisTemplate;

    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public SignupDto signup(
            String username,
            String password
    ) {
        if (userRepository.findByUsername(username).isPresent()) {
            throw new CustomErrorException(ErrorCode.DuplicatedUserNameError);
        }
        Users user = userRepository.save(new Users(username, passwordEncoder.encode(password), "ROLE_USER"));
        return SignupDto.fromEntity(user);
    }

    public void logout(String accessToken, String refreshToken) {
        ValueOperations<String, String> valueOperations = redisTemplate.opsForValue();

        String resolvedAccessToken = jwtTokenProvider.resolveToken(accessToken);
        String resolvedRefreshToken = jwtTokenProvider.resolveToken(refreshToken);

        if (resolvedAccessToken == null || resolvedRefreshToken == null) {
            throw new CustomErrorException(ErrorCode.NotValidRequestError);
        }

        String savedAccessToken = valueOperations.get(resolvedRefreshToken);
        if (savedAccessToken == null) {
            throw new CustomErrorException(ErrorCode.NoSuchRefreshTokenError);
        }

        if (!resolvedAccessToken.equals(savedAccessToken)) {
            // RefreshToken이 탈취 당한 것으로 판단
            valueOperations.getAndDelete(resolvedRefreshToken);
            throw new CustomErrorException(ErrorCode.NoSuchAccessTokenError);
        }

        valueOperations.getAndDelete(resolvedRefreshToken);
    }

    public ReIssueTokenDto reIssueToken(String accessToken, String refreshToken) {
        ValueOperations<String, String> valueOperations = redisTemplate.opsForValue();

        String resolvedAccessToken = jwtTokenProvider.resolveToken(accessToken);
        String resolvedRefreshToken = jwtTokenProvider.resolveToken(refreshToken);

        if (resolvedAccessToken == null || resolvedRefreshToken == null) {
            throw new CustomErrorException(ErrorCode.NotValidRequestError);
        }

        String savedAccessToken = valueOperations.get(resolvedRefreshToken);
        if (savedAccessToken == null) {
            throw new CustomErrorException(ErrorCode.NoSuchRefreshTokenError);
        }

        if (!resolvedAccessToken.equals(savedAccessToken)) {
            // RefreshToken이 탈취 당한 것으로 판단
            valueOperations.getAndDelete(resolvedRefreshToken);
            throw new CustomErrorException(ErrorCode.NoSuchAccessTokenError);
        }

        // AccessToken 유효성 및 만료여부 확인
        boolean isExpiredAccessToken = jwtTokenProvider.isExpiredAccessToken(resolvedAccessToken);
        if (!isExpiredAccessToken) {
            // RefreshToken이 탈취 당한 것으로 판단
            valueOperations.getAndDelete(resolvedRefreshToken);
            throw new CustomErrorException(ErrorCode.NotExpiredAccessTokenError);
        }

        String reIssuedAccessToken = jwtTokenProvider.reIssueAccessToken(resolvedAccessToken);
        valueOperations.getAndDelete(resolvedRefreshToken);
        valueOperations.set(resolvedRefreshToken, reIssuedAccessToken);
        return ReIssueTokenDto.of(reIssuedAccessToken);
    }
}
