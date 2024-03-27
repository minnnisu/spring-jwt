package org.minnnisu.springjwt.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.minnnisu.springjwt.constant.ErrorCode;
import org.minnnisu.springjwt.exception.ErrorResponseDto;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import java.io.IOException;

@Slf4j
public class LoginFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        HttpStatus httpStatus = HttpStatus.INTERNAL_SERVER_ERROR;
        ErrorResponseDto errorResponseDto = ErrorResponseDto.of(ErrorCode.InternalServerError.name(), ErrorCode.InternalServerError.getMessage());

        if (exception instanceof BadCredentialsException ||
                exception instanceof UsernameNotFoundException ||
                exception instanceof InternalAuthenticationServiceException) {
            httpStatus = HttpStatus.BAD_REQUEST;
            errorResponseDto = ErrorResponseDto.of(ErrorCode.UserNotFoundError.name(),"아이디 혹은 비밀번호를 다시 한번 확인해 주세요");
        }

        String jsonResponse = objectMapper.writeValueAsString(errorResponseDto);

        response.setStatus(httpStatus.value());
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(jsonResponse);
    }
}