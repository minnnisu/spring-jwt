package org.minnnisu.springjwt.user;

import lombok.Data;

@Data
public class UserLoginRequestDto {
    private String username;
    private String password;
}