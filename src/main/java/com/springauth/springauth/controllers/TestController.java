package com.springauth.springauth.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins="*", maxAge = 3600)
@RestController
@RequestMapping("api/tes")
public class TestController {

    @GetMapping("/all")
    public String AllAccess(){
        return "Public content";
    }

    @GetMapping("/mod")
    @PreAuthorize("hasRole('MODERATOR')")
    public String moderatorAccess(){
        return "Moderator Board";
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER')  or hasRole('MODERATOR') or hasRole('ADMIN')")
    public String UserAccess(){
        return "User Content";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminAccess(){
        return "Admin Board";
    }
}
