package com.tutorial.api;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class App {

   public static void main(String[] args) {
      SpringApplication.run(App.class, args);
   }

   /*
    * Source: https://blog.marcosbarbero.com/password-encoder-migration-spring-security-5/ PasswordEncoderFactories.createDelegatingPasswordEncoder -
    * support multiple password encoders based on a prefix. The password is stored like this: --
    * {bcrypt}$2a$10$vCXMWCn7fDZWOcLnIEhmK.74dvK1Eh8ae2WrWlhr2ETPLoxQctN4. -- {noop}plaintextpassword I used this for development purposes only. I
    * think in a production its better to use a specific BycryptEncoder if the system needs only to support one password encoder.
    * 
    * Note, this bean is define here to avoid circular dependency of WebSecurityConfig->UserDetailService->UserService. UserService needs the bean of
    * PasswordEncoder, previously the PasswordEncoder bean was define in WebSecurityConfig.
    */
   @Bean
   public PasswordEncoder passwordEncoder() {
      return PasswordEncoderFactories.createDelegatingPasswordEncoder();
   }
}
