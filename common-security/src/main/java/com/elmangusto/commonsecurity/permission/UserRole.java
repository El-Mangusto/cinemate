package com.elmangusto.commonsecurity.permission;

import java.util.EnumSet;
import java.util.Set;

public enum UserRole {

    USER(Set.of(
            Permission.MOVIE_VIEW
    )),

    ADMIN(Set.of(
            Permission.MOVIE_VIEW,
            Permission.MOVIE_CREATE,
            Permission.MOVIE_UPDATE,
            Permission.MOVIE_DELETE,
            Permission.USER_VIEW
    )),

    SUPER_ADMIN(EnumSet.allOf(Permission.class));

    private final Set<Permission> permissions;

    UserRole(Set<Permission> permissions) {
        this.permissions = permissions;
    }

    public Set<Permission> getPermissions() {
        return permissions;
    }

    public boolean hasPermission(Permission permission) {
        return permissions.contains(permission);
    }
}
