package org.example.backend.controller;

import lombok.RequiredArgsConstructor;
import org.example.backend.auth.JWTCore;
import org.example.backend.dto.SignInDto;
import org.example.backend.dto.SignUpDto;
import org.example.backend.model.User;
import org.example.backend.repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class MainController {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JWTCore jwtCore;
    private final AuthenticationManager authenticationManager;

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody SignUpDto signUpDto) {
        if (userRepository.findByUsername(signUpDto.getUsername()).isPresent()) {
            return ResponseEntity.badRequest().body("Username is already in use");
        }
        if (userRepository.findByEmail(signUpDto.getEmail()).isPresent()) {
            return ResponseEntity.badRequest().body("Email is already in use");
        }
        String hashedPassword = passwordEncoder.encode(signUpDto.getPassword());
        User user = new User();
        user.setUsername(signUpDto.getUsername());
        user.setEmail(signUpDto.getEmail());
        user.setPassword(hashedPassword);
        userRepository.save(user);
        return ResponseEntity.ok().body(user);
    }

    @PostMapping("/singin")
    public ResponseEntity<?> signin(@RequestBody SignInDto signInDto) {
        Authentication authentication = null;
        try {
            authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(signInDto.getUsername(), signInDto.getPassword()));
        } catch (BadCredentialsException e) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtCore.getToken(authentication);
        return ResponseEntity.ok(jwt);
    }
}
