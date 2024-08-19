package com.example.semi.service;

import com.example.semi.model.User;
import com.example.semi.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * 새로운 사용자를 등록하는 메서드입니다.
     * 이 메서드는 사용자 정보를 받아 비밀번호를 인코딩한 후 데이터베이스에 저장합니다.
     *
     * @param user 등록할 사용자 객체
     */
    public void registerUser(User user) {
        // 비밀번호를 인코딩합니다.
        // Spring Security의 PasswordEncoder를 사용하여 비밀번호를 안전하게 저장할 수 있도록 인코딩합니다.
        user.setPassword(passwordEncoder.encode(user.getPassword()));

        // 사용자 정보를 데이터베이스에 저장합니다.
        // 인코딩된 비밀번호를 포함한 사용자 객체를 UserRepository를 통해 저장합니다.
        userRepository.save(user);
    }
}
