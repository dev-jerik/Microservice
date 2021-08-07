package com.tutorial.api.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.tutorial.api.filter.JwtAuthorizationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

   private final AuthenticationEntryPointConfig unauthorizedHandler;

   public WebSecurityConfig(AuthenticationEntryPointConfig unauthorizedHandler) {
      this.unauthorizedHandler = unauthorizedHandler;
   }

   @Override
   protected void configure(HttpSecurity http) throws Exception {
      http.cors()
            .and()
            .csrf().disable()
            .exceptionHandling().authenticationEntryPoint(unauthorizedHandler)
            .and()
            .authorizeRequests()
//            .antMatchers("/books/{id}").hasRole("USER") // Spring security automatically append ROLE_
            .antMatchers("/books").hasAuthority("book:add")
            .anyRequest().authenticated()
            .and()
            .addFilterBefore(new JwtAuthorizationFilter(), BasicAuthenticationFilter.class)
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
   }
}
