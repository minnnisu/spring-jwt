package org.minnnisu.springjwt.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.minnnisu.springjwt.constant.ErrorCode;
import org.minnnisu.springjwt.constant.TokenType;
import org.minnnisu.springjwt.domain.Users;
import org.minnnisu.springjwt.dto.ReIssueTokenDto;
import org.minnnisu.springjwt.dto.SignupDto;
import org.minnnisu.springjwt.exception.CustomErrorException;
import org.minnnisu.springjwt.provider.JwtTokenProvider;
import org.minnnisu.springjwt.repository.UserRepository;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {
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

    public void logout(String refreshToken) {
        String resolvedRefreshToken = jwtTokenProvider.resolveToken(refreshToken);
        if (resolvedRefreshToken == null) {
            throw new CustomErrorException(ErrorCode.NotValidRequestError);
        }

        jwtTokenProvider.validateRefreshToken(resolvedRefreshToken);
        // TODO: DB에 블랙리스트로 등록
    }

    public ReIssueTokenDto reIssueToken(String accessToken, String refreshToken) {
        String resolvedAccessToken = jwtTokenProvider.resolveToken(accessToken);
        String resolvedRefreshToken = jwtTokenProvider.resolveToken(refreshToken);

        if (resolvedAccessToken == null || resolvedRefreshToken == null) {
            throw new CustomErrorException(ErrorCode.NotValidRequestError);
        }

        // AccessToken 유효성 및 만료여부 확인
        boolean isExpiredAccessToken = jwtTokenProvider.isExpiredAccessToken(resolvedAccessToken);
        if (!isExpiredAccessToken) {
            throw new CustomErrorException(ErrorCode.NotExpiredAccessTokenError);
        }

        jwtTokenProvider.validateRefreshToken(resolvedRefreshToken);
        // TODO: DB를 조회하여 해당 토큰이 존재하는지, 블랙리스트로 등록되었는지 확인
        String reIssuedAccessToken = jwtTokenProvider.reIssueAccessToken(resolvedAccessToken);
        return ReIssueTokenDto.of(reIssuedAccessToken);
    }
}
