package com.example.demo.controller;


import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class SimpleUserBehaviourController {


    @RequestMapping(value="/user")
    @GetMapping
    public Principal user(Principal principal) {
        return principal;
    }

    @RequestMapping("/account")
    public String home(Principal user) {
        return "Hello " + user.getName();
    }


    @RequestMapping(value="/unauthenticated")
    @GetMapping
    public String unauthenticated() {
        return "redirect:/?error=true";
    }


}
