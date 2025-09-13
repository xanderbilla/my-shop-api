package com.shop.auth.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class InfoController {

    @GetMapping("/info")
    public String getAuthInfo() {
        return "Auth Service Running";
    }
    
}