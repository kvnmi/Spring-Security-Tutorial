package com.example.demo.auth;

import java.util.Optional;

public interface ApplicationUserDAO {
     Optional<ApplicationUser> selectUserByUsername(String username);
}
