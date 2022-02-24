package com.jwt.springsecurityjwt.repository;

import com.jwt.springsecurityjwt.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {

   public User findByUsername(String username);
}
