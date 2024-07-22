package org.example.backend.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/secured")
public class SecurityController {

    @GetMapping("/user")
    public String getUser(Principal principal) {
        if (principal == null) {
            return "You are not logged in";
        }
        return principal.getName();
    }
}
