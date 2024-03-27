package com.example.springsecurity6.common;

import com.example.springsecurity6.UserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class JwtAuthorizationFilter {

    private final UserDetailsService userDetailsService;
}
