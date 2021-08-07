package com.tutorial.api.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.tutorial.api.filter.JwtAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
   private final PasswordEncoder passwordEncoder;
   private final UserDetailsService userDetailsService;

   public WebSecurityConfig(PasswordEncoder passwordEncoder, UserDetailsService userDetailsService) {
      this.passwordEncoder = passwordEncoder;
      this.userDetailsService = userDetailsService;
   }

   @Override
   protected void configure(HttpSecurity http) throws Exception {
      http.cors()
            .and()
            .csrf().disable()
            .authorizeRequests()
            .anyRequest().authenticated()
            .and()
            .addFilter(new JwtAuthenticationFilter(authenticationManagerBean()))
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
   }

   @Override
   protected void configure(AuthenticationManagerBuilder auth) throws Exception {
      auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
   }

   @Bean
   @Override
   public AuthenticationManager authenticationManagerBean() throws Exception {
      return super.authenticationManagerBean();
   }

}
