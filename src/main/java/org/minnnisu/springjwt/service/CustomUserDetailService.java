package org.minnnisu.springjwt.user;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) {
        User user = userRepository.findByUsername(username).orElseThrow(() -> {
                    System.out.println("해당하는 유저를 찾을 수 없습니다");
                    return new UsernameNotFoundException("해당하는 유저를 찾을 수 없습니다.");
                });
        return user;
    }


    // 해당하는 User 의 데이터가 존재한다면 UserDetails 객체로 만들어서 리턴
    /**
     * 여기서 PasswordEncoder를 통해 UserDetails 객체를 생성할 때 encoding을 해줌 => 왜냐하면 Spring Security는 사용자 검증을 위해 encoding된 password와 그렇지 않은 password를 비교하기 때문
     * 실제로는 DB 자체에 encoding된 password 값을 갖고 있고 그냥 memer.getPassword()로 encoding된 password를 꺼내는 것이 좋지만, 예제에서는 편의를 위해 검증 객체를 생성할 때 encoding을 해줌.
     */
    private UserDetails createUserDetails(User user) {
        return User.builder()
                .username(user.getUsername())
                .password(passwordEncoder.encode(user.getPassword()))
                .roles(List.of(user.getRoles().toArray(new String[0])))
                .build();
    }
}
