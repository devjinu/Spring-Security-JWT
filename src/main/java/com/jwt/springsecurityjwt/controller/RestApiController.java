package com.jwt.springsecurityjwt.controller;

import com.jwt.springsecurityjwt.model.User;
import com.jwt.springsecurityjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class RestApiController {

    private final UserRepository userRepository;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("home")
    public String home(){
        return "<h1>home</h1>";
    }

    @PostMapping("token")
    public String token(){
        return "<h1>token</h1>";
    }

    @PostMapping("join")
    public String join(@RequestBody User user){
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setRoles("ROLE_USER");
        userRepository.save(user);
        return "회원가입완료";
    }

    // user,manager,admin 접근 가능
    @GetMapping("/api/v1/user")
    public String user(){
        return "<h1>user</h1>";
    }
    // manager,admin 접근 가능
    @GetMapping("/api/v1/manager")
    public String manager(){
        return "<h1>manager</h1>";
    }
    // admin 접근 가능
    @GetMapping("/api/v1/admin")
    public String admin(){
        return "<h1>admin</h1>";
    }

}
