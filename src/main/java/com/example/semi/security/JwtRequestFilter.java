package com.example.semi.security;

import com.example.semi.util.JwtTokenUtil;
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    @Autowired
    private UserDetailsService jwtUserDetailsService;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    /**
     * JWT 토큰을 필터링하는 핵심 메서드입니다.
     * 요청의 Authorization 헤더에서 JWT 토큰을 추출하여 유효성을 검사하고,
     * 유효한 토큰이 있는 경우 사용자 정보를 로드하여 Spring Security의 인증 컨텍스트에 설정합니다.
     *
     * @param request  HttpServletRequest 객체
     * @param response HttpServletResponse 객체
     * @param filterChain FilterChain 객체
     * @throws ServletException 서블릿 예외가 발생할 수 있음
     * @throws IOException 입출력 예외가 발생할 수 있음
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // 요청 헤더에서 Authorization 값 가져오기
        final String requestTokenHeader = request.getHeader("Authorization");

        String username = null;
        String jwtToken = null;

        // JWT 토큰이 Bearer 문자열로 시작하는지 확인
        if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
            // Bearer 문자열 이후의 실제 JWT 토큰을 추출
            jwtToken = requestTokenHeader.substring(7);
            try {
                // JWT 토큰에서 사용자 이름 추출
                username = jwtTokenUtil.getUsernameFromToken(jwtToken);
            } catch (IllegalArgumentException e) {
                System.out.println("Unable to get JWT Token");  // JWT 토큰을 가져올 수 없는 경우
            } catch (ExpiredJwtException e) {
                System.out.println("JWT Token has expired");  // JWT 토큰이 만료된 경우
            }
        } else {
            // JWT 토큰이 Bearer 문자열로 시작하지 않는 경우 경고 로그 출력
            logger.warn("JWT Token does not begin with Bearer String");
        }

        // 사용자 이름이 존재하고, SecurityContext에 인증 정보가 없는 경우
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // 사용자 정보를 로드
            UserDetails userDetails = this.jwtUserDetailsService.loadUserByUsername(username);
            // JWT 토큰이 유효한지 확인
            if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {
                // 유효한 토큰인 경우 인증 객체를 생성하고 설정
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                // 요청 세부 정보를 설정
                usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                // Spring Security 컨텍스트에 인증 정보 설정
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
        }
        // 필터 체인에 요청과 응답을 전달하여 다음 필터로 진행
        filterChain.doFilter(request, response);
    }
}
