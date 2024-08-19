package com.example.semi.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtRequestFilter jwtRequestFilter;

    /**
     * WebSecurityConfig 생성자입니다.
     * JwtAuthenticationEntryPoint와 JwtRequestFilter를 주입받아 초기화합니다.
     *
     * @param jwtAuthenticationEntryPoint 인증이 실패할 경우 동작할 진입점
     * @param jwtRequestFilter 모든 요청에 대해 JWT를 검증하는 필터
     */
    public WebSecurityConfig(JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint, JwtRequestFilter jwtRequestFilter) {
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtRequestFilter = jwtRequestFilter;
    }

    /**
     * 비밀번호를 암호화하기 위한 PasswordEncoder 빈을 생성합니다.
     * BCryptPasswordEncoder를 사용하여 비밀번호를 암호화합니다.
     *
     * @return PasswordEncoder 비밀번호 암호화 도구
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();  // BCrypt 알고리즘을 사용하여 비밀번호를 암호화
    }

    /**
     * AuthenticationManager를 구성합니다.
     * Spring Security의 인증 과정을 처리하는 핵심 매니저입니다.
     *
     * @param authenticationConfiguration AuthenticationConfiguration을 주입받아 AuthenticationManager를 생성
     * @return AuthenticationManager 인증 관리자
     * @throws Exception 예외가 발생할 수 있습니다.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();  // AuthenticationManager를 빈으로 등록
    }

    /**
     * SecurityFilterChain을 구성합니다.
     * HTTP 보안 설정을 정의하고 JWT 필터를 추가합니다.
     *
     * @param http HttpSecurity 객체를 통해 웹 보안을 설정
     * @return SecurityFilterChain 보안 필터 체인
     * @throws Exception 예외가 발생할 수 있습니다.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())  // CSRF(Cross-Site Request Forgery) 보호 기능을 비활성화
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/authenticate", "/register", "/users/register").permitAll()  // 인증이 필요 없는 경로 설정
                        .anyRequest().authenticated()  // 나머지 모든 요청은 인증 필요
                )
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(jwtAuthenticationEntryPoint)  // 인증 실패 시 동작할 진입점 설정
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)  // 세션을 사용하지 않고 JWT 기반으로 인증 처리
                );

        // JWTRequestFilter를 UsernamePasswordAuthenticationFilter 앞에 추가
        http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();  // 설정된 보안 필터 체인을 반환
    }

}
