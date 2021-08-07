package com.tutorial.api.filter;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Date;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tutorial.api.entity.user.SpringSecurityUser;
import com.tutorial.api.entity.user.User;

import lombok.extern.slf4j.Slf4j;

/**
 * This class will be responsible for authenticating the user.
 * We don't need to create a login controller because spring security already have a default Endpoint("/login") for login.
 * 
 * @author Jerik
 * @email jgbeltran.dev@gmail.com
 */
@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
   private final AuthenticationManager authenticationManager;

   /**
    * Constructor for dependency injection.
    */
   public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
      this.authenticationManager = authenticationManager;
      setFilterProcessesUrl("/auth/login");
   }

   @Override
   public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

      User user = null;
      try {
         user = new ObjectMapper().readValue(request.getInputStream(), User.class);
         return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
      } catch (BadCredentialsException e) {
         log.warn(e.getMessage());
         throw e;
      } catch (Exception e) {
         log.error(ExceptionUtils.getStackTrace(e));
         throw new RuntimeException(e);
      }

   }

   @Override
   protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult)
         throws IOException, ServletException {
      SpringSecurityUser user = (SpringSecurityUser) authResult.getPrincipal();
      int expiry = 180000;
      String token = JWT.create().withSubject(user.getUsername())
            .withClaim("roles", user.getAuthorities().stream().map(x -> x.getAuthority()).collect(Collectors.joining(",")))
            .withExpiresAt(new Date(System.currentTimeMillis() + expiry))
            .sign(Algorithm.HMAC512("mysecret".getBytes()));

      response.addHeader("Authorization", "Bearer " + token);
   }

   @Override
   protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed)
         throws IOException, ServletException {

      String warnMessage = "Username or Password is incorrect.";

      PrintWriter writer = response.getWriter();
      writer.println(warnMessage);

      response.setStatus(HttpStatus.UNAUTHORIZED.value());
      log.warn(warnMessage);
   }
}
