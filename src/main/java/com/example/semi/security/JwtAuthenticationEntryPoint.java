package com.example.semi.security;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    /**
     * 인증되지 않은 사용자가 보호된 리소스에 접근하려 할 때 호출됩니다.
     * 이 메서드는 Spring Security가 인증 오류를 감지할 때 실행되며,
     * 클라이언트에 HTTP 401 Unauthorized 에러를 반환합니다.
     *
     * @param request  HttpServletRequest 객체
     * @param response HttpServletResponse 객체
     * @param authException 발생한 인증 예외
     * @throws IOException 입출력 예외가 발생할 수 있음
     * @throws ServletException 서블릿 예외가 발생할 수 있음
     */
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {
        // 인증 실패 시 클라이언트에게 401 Unauthorized 에러를 응답으로 보냄
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
    }
}
