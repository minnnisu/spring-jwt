package org.minnnisu.springjwt.service;

import lombok.RequiredArgsConstructor;
import org.minnnisu.springjwt.constant.ErrorCode;
import org.minnnisu.springjwt.domain.Users;
import org.minnnisu.springjwt.exception.CustomErrorException;
import org.minnnisu.springjwt.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) {
        Users users = userRepository.findByUsername(username).orElseThrow(() ->
                new CustomErrorException(ErrorCode.UserNotFoundError)
        );

        return org.springframework.security.core.userdetails.User.builder()
                .username(users.getUsername())
                .password(users.getPassword())
                .roles(users.getAuthority().substring(5))
                .build();
    }
}

