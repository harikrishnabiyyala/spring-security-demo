package com.example.spring_security_demo.controller;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {


    @GetMapping("/hello")
    public String getWelcome(){
        return "Hello welcome to the application";
    }

    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    @GetMapping("/user")
    public String userEndPoint(){
        return "Hello user welcome to the application";
    }
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String adminEndPoint(){
        return "Hello Admin welcome to the application";
    }
}
