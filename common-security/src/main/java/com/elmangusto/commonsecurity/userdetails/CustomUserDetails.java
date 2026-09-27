package com.elmangusto.commonsecurity.userdetails;

import com.elmangusto.commonsecurity.permission.Permission;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

@Getter
public class CustomUserDetails implements UserDetails {

    private final Long id;
    private final String username;
    private final Set<Permission> permissions;

    public CustomUserDetails(Long id, String username, Set<Permission> permissions) {
        this.id = id;
        this.username = username;
        this.permissions = permissions;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return permissions.stream()
                .map(p -> new SimpleGrantedAuthority(p.name()))
                .collect(Collectors.toSet());
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return username;
    }
}