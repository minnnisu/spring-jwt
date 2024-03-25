package org.minnnisu.springjwt.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.minnnisu.springjwt.constant.ErrorCode;
import org.minnnisu.springjwt.domain.Users;
import org.minnnisu.springjwt.dto.TokenDto;
import org.minnnisu.springjwt.exception.AlreadyRegisteredUserException;
import org.minnnisu.springjwt.exception.CustomErrorException;
import org.minnnisu.springjwt.exception.UserNotFoundException;
import org.minnnisu.springjwt.provider.JwtTokenProvider;
import org.minnnisu.springjwt.repository.UserRepository;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final JwtTokenProvider jwtTokenProvider;

    /**
     * 유저 등록
     *
     * @param username username
     * @param password password
     * @return 유저 권한을 가지고 있는 유저
     */
    public Users signup(
            String username,
            String password
    ) {
        if (userRepository.findByUsername(username).isPresent()) {
            throw new CustomErrorException(ErrorCode.DuplicatedUserNameError);
        }
        return userRepository.save(new Users(username, passwordEncoder.encode(password), "ROLE_USER"));
    }

    /**
     * 관리자 등록
     *
     * @param username username
     * @param password password
     * @return 관리자 권한을 가지고 있는 유저
     */
    public Users signupAdmin(
            String username,
            String password
    ) {
        if (userRepository.findByUsername(username) != null) {
            throw new AlreadyRegisteredUserException();
        }
        return userRepository.save(new Users(username, passwordEncoder.encode(password), "ROLE_ADMIN"));
    }

    @Transactional
    public TokenDto login(String username, String password) {
        // 1. Login ID/PW 를 기반으로 Authentication 객체 생성
        // 이때 authentication 는 인증 여부를 확인하는 authenticated 값이 false
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);

        // 2. 실제 검증 (사용자 비밀번호 체크)이 이루어지는 부분
        // authenticate 매서드가 실행될 때 CustomUserDetailsService 에서 만든 loadUserByUsername 메서드가 실행
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);

        // 3. 인증 정보를 기반으로 JWT 토큰 생성
        TokenDto tokenDto = jwtTokenProvider.generateToken(authentication);

        return tokenDto;
    }

    public Users findByUsername(String username) {
        return userRepository.findByUsername(username).orElseThrow(UserNotFoundException::new);
    }

    public List<Users> findAll() {
        return userRepository.findAll();
    }
}