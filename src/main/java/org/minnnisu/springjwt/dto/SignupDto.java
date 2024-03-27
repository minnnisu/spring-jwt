package org.minnnisu.springjwt.dto;

import lombok.*;
import org.minnnisu.springjwt.domain.Users;

@Getter
@Setter
@AllArgsConstructor
@Builder
public class SignupDto {
    private String username;

    public static SignupDto fromEntity(Users users){
        return SignupDto.builder()
                .username(users.getUsername())
                .build();
    }
}
