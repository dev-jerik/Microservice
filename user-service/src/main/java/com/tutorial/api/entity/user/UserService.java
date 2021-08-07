package com.tutorial.api.entity.user;

import java.util.Optional;

import org.springframework.stereotype.Service;

@Service
public class UserService {
   private final UserRepository userRepository;

   // Dependency Injection
   public UserService(UserRepository userRepository) {
      this.userRepository = userRepository;
   }
   
   public Optional<User> findUserByUsername(String username) {
      return userRepository.findByUsername(username);
   }
}
