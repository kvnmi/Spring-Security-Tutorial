package com.example.demo.jwt;

public class JWTUser {
    public String username;
    public String password;

    public String getPassword() {
        return password;
    }

    public String getUsername() {
        return username;
    }

    public JWTUser() {
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
