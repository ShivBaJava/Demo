package com.test.security.service;

import com.test.security.dto.UserDTO;
import com.test.security.entity.Users;
import com.test.security.repo.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }
    // Register a new user
    public Users registerUser(UserDTO userDTO) {
        // Check if the user already exists
        Optional<Users> existingUser = userRepository.findByUsername(userDTO.getUsername());
        if (existingUser.isPresent()) {
            throw new RuntimeException("Username is already taken");
        }

        // Encrypt the password
        String encryptedPassword = passwordEncoder.encode(userDTO.getPassword());

        // Create and save the new user
        Users newUser = new Users();
        newUser.setUsername(userDTO.getUsername());
        newUser.setPassword(encryptedPassword);
        newUser.setRoles(userDTO.getRoles() != null ? userDTO.getRoles() : List.of("ROLE_USER")); // Default to ROLE_USER
        return userRepository.save(newUser);
    }

}
