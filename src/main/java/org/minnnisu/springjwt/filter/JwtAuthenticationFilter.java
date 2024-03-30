package org.minnnisu.springjwt.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.minnnisu.springjwt.constant.ErrorCode;
import org.minnnisu.springjwt.exception.CustomErrorException;
import org.minnnisu.springjwt.exception.ErrorResponseDto;
import org.minnnisu.springjwt.provider.JwtTokenProvider;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.lang.model.type.ErrorType;
import java.io.IOException;

/**
 * JwtAuthenticationFilter는 클라이언트 요청 시 JWT 인증을 하기위해 설치하는 커스텀 필터로, UsernamePasswordAuthenticationFilter 이전에 실행됨
 * 이 말은 JwtAuthenticationFilter를 통과하면 UsernamePasswordAuthenticationFilter 이후의 필터는 통과한 것으로 본다는 뜻입니다. = username+password를 통한 인증을 JWT를 통해 수행한다는 것!
 *
 * @author rimsong
 */

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtTokenProvider jwtTokenProvider;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain
    ) throws ServletException, IOException {
        log.info("JwtAuthenticationFilter 호출");

        String accessToken = resolveAccessToken(request);

        if (accessToken == null) {
            chain.doFilter(request, response);
            return;
        }

        try {
            jwtTokenProvider.validateAccessToken(accessToken);
            Authentication authentication = jwtTokenProvider.getAuthentication(accessToken);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            chain.doFilter(request, response);
        } catch (Exception e) {
            if (request.getRequestURI().equals("/auth/refreshToken") && request.getMethod().equals(HttpMethod.POST.name())) {
                chain.doFilter(request, response);
            }

            if (request.getRequestURI().equals("/auth/logout") && request.getMethod().equals(HttpMethod.POST.name())) {
                chain.doFilter(request, response);
            }
            jwtExceptionHandler(response, e);
        }
    }

    // Request Header 에서 토큰 정보 추출
    private String resolveAccessToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer")) {
            return bearerToken.substring(7);
        }
        return null;
    }


    // 토큰에 대한 오류가 발생했을 때, 커스터마이징해서 Exception 처리 값을 클라이언트에게 알려준다.
    public void jwtExceptionHandler(HttpServletResponse response, Exception e) {
        log.info("Exception Info:" + e.getMessage());
        ErrorCode errorCode = ErrorCode.InternalServerError;
        if (e instanceof CustomErrorException) {
            errorCode = ((CustomErrorException) e).getErrorCode();
        }

        response.setStatus(errorCode.getHttpStatus().value());
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        try {
            String json = new ObjectMapper().writeValueAsString(ErrorResponseDto.of(errorCode.name(), errorCode.getMessage()));
            response.getWriter().write(json);
        } catch (Exception ex) {
            log.error(ex.getMessage());
        }
    }
}
