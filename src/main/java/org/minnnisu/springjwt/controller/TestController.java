package org.minnnisu.springjwt.controller;

import jakarta.annotation.Resource;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.minnnisu.springjwt.constant.ErrorCode;
import org.minnnisu.springjwt.domain.Users;
import org.minnnisu.springjwt.exception.CustomErrorException;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class TestController {

    @GetMapping("/test/user")
    public ResponseEntity<String> testAuthenticatedUser(@AuthenticationPrincipal Users users){
        return new ResponseEntity<>("로그인한 유저: " + users.getUsername(), HttpStatus.OK);
    }

    @GetMapping("/test/noUser")
    public ResponseEntity<String> testNoAuthenticatedUser(){
        return new ResponseEntity<>("로그인 하지 않은 유저", HttpStatus.OK);
    }

}
