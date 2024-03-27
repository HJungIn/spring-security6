package com.example.springsecurity6.common;

import com.example.springsecurity6.User;
import com.example.springsecurity6.UserDetailsService;
import com.example.springsecurity6.UserDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Arrays;

@Slf4j
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;

    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        log.info("2.CustomAuthenticationProvider");

        UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) authentication;

        // AuthenticationFilter에서 생성된 토큰으로부터 ID, PW를 조회
        String loginId = token.getName();
        String userPassword = (String) token.getCredentials();

        // Spring security - UserDetailsService를 통해 DB에서 username으로 사용자 조회
        UserDto securityUserDetailsDto = new UserDto((User) userDetailsService.loadUserByUsername(loginId));

        // 대소문자를 구분하는 matches() 메서드로 db와 사용자가 제출한 비밀번호를 비교
        if (!bCryptPasswordEncoder().matches(userPassword, securityUserDetailsDto.getPassword())) {
            throw new BadCredentialsException(securityUserDetailsDto.getName() + "Invalid password");
        }

        // 인증이 성공하면 인증된 사용자의 정보와 권한을 담은 새로운 UsernamePasswordAuthenticationToken을 반환한다.
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(securityUserDetailsDto, userPassword, Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")));
        System.out.println("authToken = " + authToken);
//        SecurityContextHolder.getContext().setAuthentication(authToken);
        return authToken;
    }

    // AuthenticationProvider가 특정 Authentication 타입을 지원하는지 여부를 반환
    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
