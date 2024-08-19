package com.example.semi.controller;

import com.example.semi.model.User;
import com.example.semi.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
public class UserController {

    @Autowired
    private UserService userService;

    /**
     * 사용자 등록 요청을 처리하는 메서드입니다.
     * 클라이언트로부터 사용자 정보를 받아서 UserService를 통해 사용자를 등록합니다.
     *
     * @param user 클라이언트로부터 전달된 사용자 정보가 담긴 User 객체
     * @return 등록 성공 메시지를 포함한 ResponseEntity 객체
     */
    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody User user) {
        userService.registerUser(user);
        return ResponseEntity.ok("User registered successfully!");
    }
}
