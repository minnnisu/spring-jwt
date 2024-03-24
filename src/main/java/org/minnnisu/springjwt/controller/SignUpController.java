package org.minnnisu.springjwt.controller;

import lombok.RequiredArgsConstructor;
import org.minnnisu.springjwt.dto.UserRegisterDto;
import org.minnnisu.springjwt.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * 회원가입 Controller
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class SignUpController {

    private final UserService userService;

    @PostMapping("/signup")
    public ResponseEntity<String> signup(
            @RequestBody UserRegisterDto userDto
    ) {
        userService.signup(userDto.getUsername(), userDto.getPassword());
        // 회원가입 후 로그인 페이지로 이동
        return new ResponseEntity<String>("회원가입에 성공하였습니다.", HttpStatus.CREATED);
    }
}
