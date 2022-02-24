package com.jwt.springsecurityjwt.config.auth;

import com.jwt.springsecurityjwt.model.User;
import com.jwt.springsecurityjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// http://localhost:8080/login -> 동작x (form로그인 사용x)
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("PrincipalDetailsService의 UserDetailsService() ");
        User user = userRepository.findByUsername(username);
        return new PrincipalDetails(user);

    }
}
