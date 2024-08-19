package com.example.semi.controller;

import com.example.semi.model.JwtRequest;
import com.example.semi.model.JwtResponse;
import com.example.semi.util.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

@RestController
@CrossOrigin
public class AuthenticationController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private UserDetailsService jwtUserDetailsService;

    /**
     * 사용자의 인증 요청을 처리하고, 인증이 성공하면 JWT 토큰을 생성하여 반환합니다.
     *
     * @param authenticationRequest 사용자 인증 요청을 담은 JwtRequest 객체
     * @return JWT 토큰을 담은 JwtResponse 객체를 ResponseEntity로 반환
     * @throws Exception 인증 실패 시 예외를 던집니다.
     */
    @PostMapping("/authenticate")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody JwtRequest authenticationRequest) throws Exception {
        try {
            // 사용자 인증을 시도합니다.
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword())
            );
        } catch (BadCredentialsException e) {
            // 인증이 실패하면 예외를 던집니다.
            throw new Exception("INVALID_CREDENTIALS", e);
        }

        // 인증이 성공하면 사용자 세부 정보를 로드합니다.
        final UserDetails userDetails = jwtUserDetailsService
                .loadUserByUsername(authenticationRequest.getUsername());

        // JWT 토큰을 생성합니다.
        final String token = jwtTokenUtil.generateToken(userDetails.getUsername());

        // JWT 토큰을 포함한 응답을 반환합니다.
        return ResponseEntity.ok(new JwtResponse(token));
    }
}
