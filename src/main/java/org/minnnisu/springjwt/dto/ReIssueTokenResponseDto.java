package org.minnnisu.springjwt.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@Builder
public class ReIssueTokenResponseDto {
    private String refreshToken;

    public static ReIssueTokenResponseDto fromDto(ReIssueTokenDto reIssueTokenDto){
        return ReIssueTokenResponseDto.builder()
                .refreshToken(reIssueTokenDto.getToken())
                .build();
    }
}
