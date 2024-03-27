package com.example.springsecurity6.controller;

import com.example.springsecurity6.UserDetailsService;
import com.example.springsecurity6.UserDto;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class UserController {

    private final UserDetailsService userDetailsService;

    @PostMapping("/user")
    public void save(UserDto userDto){
        userDetailsService.save(userDto);
    }
}
