package com.example.springsecurity6;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder encoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("@@@@@@@@@@@ UserDetailsService - loadUserByUsername : "+username);
        User user = userRepository.findByName(username).orElseThrow(() -> new UsernameNotFoundException("User '" + username + "' not found"));
        return user;
    }

    public void save(UserDto userDto){
        userRepository.save(User.builder().name(userDto.getName()).password(encoder.encode(userDto.getPassword())).build());
    }
}
