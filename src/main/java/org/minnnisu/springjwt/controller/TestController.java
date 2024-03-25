package org.minnnisu.springjwt.controller;

import org.minnnisu.springjwt.domain.Users;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class TestController {

    @GetMapping("/test")
    public ResponseEntity<String> test(@AuthenticationPrincipal Users users){
        return new ResponseEntity<String>("로그인한 유저: " + users.getUsername(), HttpStatus.OK);
    }
}
