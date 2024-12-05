package com.test.security.controller;

import com.test.security.dto.LoginRequest;
import com.test.security.dto.LoginResponse;
import com.test.security.dto.UserDTO;
import com.test.security.entity.Users;
import com.test.security.jwt.JwtUtils;
import com.test.security.repo.UserRepository;
import com.test.security.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;

    public AuthController(UserService userService) {
        this.userService = userService;
    }
    @Autowired
    private JwtUtils jwtUtils;

    @Autowired(required = true)
    private AuthenticationManager authenticationManager;


    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;


    // Register new user
    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody UserDTO userDTO) {
        try {
            Users registeredUser = userService.registerUser(userDTO);
            return ResponseEntity.ok("User registered successfully");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }

    @GetMapping("/login")
    public ResponseEntity<?>  authenticateUser(@RequestBody LoginRequest loginRequest){
        try {

            // Fetch user from the database using the username
           Optional<Users> users= Optional.ofNullable(userRepository.findByUsername(loginRequest.getUserName())
                   .orElseThrow(() -> new RuntimeException("User not found")));
           Users userDetails= users.get();

            // Check if the provided password matches the stored password
            if (!passwordEncoder.matches(loginRequest.getPassword(), userDetails.getPassword())) {
                Map<String, Object> map = new HashMap<>();
                map.put("message", "Bad credentials");
                map.put("status", false);
                return new ResponseEntity<>(map, HttpStatus.UNAUTHORIZED);
            }

            String jwtToken=jwtUtils.generateTokenFromUserName(userDetails.getUsername());
            LoginResponse response = new LoginResponse(jwtToken,userDetails.getUsername(),userDetails.getRoles());
            return  ResponseEntity.ok(response);

        }catch (AuthenticationException e){
            Map<String,Object> map =  new HashMap<>();
            map.put("message","Bad credentials");
            map.put("status",false);
            return new ResponseEntity<Object>(map, HttpStatus.NOT_FOUND);
        }

    }
}
