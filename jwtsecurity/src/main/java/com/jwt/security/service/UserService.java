package com.jwt.security.service;

import com.jwt.security.model.Role;
import com.jwt.security.model.User;

import java.util.List;


public interface UserService {
    User saveUser(User user);

    Role saveRole(Role role);

    void addRoleToUser(String username, String roleName);

    User getUser(String username);

    List<User> getUsers();
}
