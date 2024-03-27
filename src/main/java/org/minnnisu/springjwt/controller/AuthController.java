package org.minnnisu.springjwt.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.minnnisu.springjwt.dto.*;
import org.minnnisu.springjwt.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {
    private final AuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<SignupResponseDto> signup(
            @RequestBody UserRegisterDto userDto
    ) {
        SignupDto signupDto = authService.signup(userDto.getUsername(), userDto.getPassword());
        // 회원가입 후 로그인 페이지로 이동
        return new ResponseEntity<>(SignupResponseDto.fromDto(signupDto), HttpStatus.CREATED);
    }

    @PostMapping("/logout")
    public ResponseEntity<LogoutResponseDto> logout(
            @RequestHeader("Authorization-refresh") String refreshToken
    ) {
        authService.logout(refreshToken);

        return new ResponseEntity<>(new LogoutResponseDto(), HttpStatus.CREATED);
    }

    @PostMapping("/refreshToken")
    public ResponseEntity<ReIssueTokenResponseDto> reIssueToken(
            @RequestHeader("Authorization") String accessToken,
            @RequestHeader("Authorization-refresh") String refreshToken
    ){
        ReIssueTokenDto reIssueTokenDto = authService.reIssueToken(accessToken, refreshToken);
        return new ResponseEntity<>(ReIssueTokenResponseDto.fromDto(reIssueTokenDto), HttpStatus.CREATED);
    }

}
