package com.example.semi.service;

import com.example.semi.model.User;
import com.example.semi.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class JwtUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    /**
     * 주어진 사용자 이름(username)에 해당하는 사용자의 세부 정보를 로드합니다.
     * 이 메서드는 Spring Security의 인증 메커니즘에서 호출됩니다.
     *
     * @param username 인증하려는 사용자의 사용자 이름
     * @return UserDetails 사용자의 세부 정보가 포함된 UserDetails 객체
     * @throws UsernameNotFoundException 사용자 이름에 해당하는 사용자를 찾을 수 없을 때 발생
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 주어진 사용자 이름으로 사용자 정보를 데이터베이스에서 찾습니다.
        Optional<User> user = userRepository.findByUsername(username);

        // 사용자가 존재하지 않으면 예외를 발생시킵니다.
        if (!user.isPresent()) {
            throw new UsernameNotFoundException("User not found with username: " + username);
        }

        // 찾은 사용자 정보를 가져옵니다.
        User foundUser = user.get();

        // Spring Security에서 사용하는 UserDetails 객체를 빌드하여 반환합니다.
        return org.springframework.security.core.userdetails.User.withUsername(foundUser.getUsername())
                .password(foundUser.getPassword())  // 이미 인코딩된 비밀번호를 설정합니다.
                .roles("USER")  // 기본적으로 모든 사용자에게 "USER" 권한을 부여합니다.
                .build();
    }
}
