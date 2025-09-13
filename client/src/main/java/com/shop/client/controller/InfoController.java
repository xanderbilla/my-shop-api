package com.shop.client.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/client")
public class InfoController {

    @GetMapping("/info")
    public String getClientInfo() {
        return "Client Service Running";
    }
    
}