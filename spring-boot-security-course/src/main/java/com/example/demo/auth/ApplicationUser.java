package com.example.demo.auth;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.Set;

public class ApplicationUser implements UserDetails {
    private final Set<? extends GrantedAuthority> grantedAuthority;
    private final String password;
    private final String username;
    private final boolean isAccountNonExpired;
    private final boolean isCredentialNonExpired;
    private final boolean isAccountNonLocked;
    private final boolean isEnabled;

    public ApplicationUser(Set<? extends GrantedAuthority> grantedAuthority, String password, String username, boolean isAccountNonExpired, boolean isCredentialNonExpired, boolean isAccountNonLocked, boolean isEnabled) {
        this.grantedAuthority = grantedAuthority;
        this.password = password;
        this.username = username;
        this.isAccountNonExpired = isAccountNonExpired;
        this.isCredentialNonExpired = isCredentialNonExpired;
        this.isAccountNonLocked = isAccountNonLocked;
        this.isEnabled = isEnabled;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return grantedAuthority;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return isAccountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return isAccountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return isCredentialNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return isEnabled;
    }
}
