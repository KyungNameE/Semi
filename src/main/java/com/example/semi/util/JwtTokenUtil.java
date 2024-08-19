package com.example.semi.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtTokenUtil {

    // HS512 알고리즘에 적합한 강력한 비밀키 생성
    // 이 키는 JWT의 서명에 사용되어 토큰의 무결성을 보호합니다.
    private Key key = Keys.secretKeyFor(SignatureAlgorithm.HS512);

    /**
     * 사용자 이름을 기반으로 JWT 토큰을 생성합니다.
     *
     * @param username 사용자 이름
     * @return 생성된 JWT 토큰
     */
    public String generateToken(String username) {
        // 클레임을 담을 맵 초기화
        Map<String, Object> claims = new HashMap<>();
        return doGenerateToken(claims, username);
    }

    /**
     * 주어진 클레임과 사용자 이름을 기반으로 JWT 토큰을 생성하고 서명합니다.
     *
     * @param claims  JWT에 포함될 클레임
     * @param subject JWT의 주체 (보통 사용자 이름)
     * @return 서명된 JWT 토큰
     */
    private String doGenerateToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims) // 클레임 설정
                .setSubject(subject) // 주체 설정 (보통 사용자 이름)
                .setIssuedAt(new Date(System.currentTimeMillis())) // 발급 시간 설정
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10)) // 만료 시간 설정 (10시간)
                .signWith(key) // HS512 알고리즘과 비밀키로 서명
                .compact(); // JWT 토큰 생성
    }

    /**
     * JWT 토큰에서 사용자 이름을 추출합니다.
     *
     * @param token JWT 토큰
     * @return 사용자 이름 (주체)
     */
    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    /**
     * JWT 토큰의 유효성을 검증합니다.
     *
     * @param token       JWT 토큰
     * @param userDetails 사용자 정보
     * @return 토큰이 유효한 경우 true, 그렇지 않으면 false
     */
    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    /**
     * JWT 토큰이 만료되었는지 확인합니다.
     *
     * @param token JWT 토큰
     * @return 토큰이 만료된 경우 true, 그렇지 않으면 false
     */
    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    /**
     * JWT 토큰에서 만료 날짜를 추출합니다.
     *
     * @param token JWT 토큰
     * @return 토큰의 만료 날짜
     */
    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    /**
     * JWT 토큰에서 특정 클레임을 추출합니다.
     *
     * @param token          JWT 토큰
     * @param claimsResolver 클레임을 추출하는 함수
     * @param <T>            클레임의 타입
     * @return 추출된 클레임
     */
    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    /**
     * 비밀키를 사용하여 JWT 토큰에서 모든 클레임을 추출합니다.
     *
     * @param token JWT 토큰
     * @return JWT의 모든 클레임
     */
    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key) // 비밀키 설정
                .build() // JWS 빌더를 생성
                .parseClaimsJws(token) // 토큰 파싱 및 클레임 추출
                .getBody(); // 클레임 반환
    }
}
