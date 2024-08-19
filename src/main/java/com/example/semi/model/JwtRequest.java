package com.example.semi.model;

public class JwtRequest {
    private String username;
    private String password;

    // 기본 생성자
    public JwtRequest() {}

    // 매개변수가 있는 생성자
    public JwtRequest(String username, String password) {
        this.username = username;
        this.password = password;
    }

    // Getter와 Setter
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
