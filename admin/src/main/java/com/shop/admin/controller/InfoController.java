package com.shop.admin.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin")
public class InfoController {

    @GetMapping("/info")
    public String getAdminInfo() {
        return "Admin Service Running";
    }
    
}