package com.tutorial.api.filter;

import java.io.IOException;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import lombok.extern.slf4j.Slf4j;

/**
 * Class that validates the bearer token from the Authorization Header.
 * 
 * @author Jerik
 * @email jgbeltran.dev@gmail.com
 */
@Slf4j
public class JwtAuthorizationFilter extends OncePerRequestFilter {

   @Override
   protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
      log.info("Intercepted by JwtAuthorizationFilter.");

      try {
         String token = parseToken(request);

         if (token != null) {
            DecodedJWT decodedJWT = JWT.require(Algorithm.HMAC512("mysecret")).build().verify(token);


            String username = decodedJWT.getSubject();
            String claims = decodedJWT.getClaim("roles").asString();

            if (username != null && claims != null) {
               // Sets of authorities
               Set<SimpleGrantedAuthority> authorities = Stream.of(claims.split(",")).map(x -> new SimpleGrantedAuthority(x))
                     .collect(Collectors.toSet());

               UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);
               authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
               SecurityContextHolder.getContext().setAuthentication(authentication);
            }

         }
      } catch (AuthenticationException e) {
         log.error(e.getMessage());
      } catch (Exception e) {
         logger.error("Cannot set user authentication: {}", e);
      }

      chain.doFilter(request, response);
   }

   private String parseToken(HttpServletRequest request) {
      int jwtStart = 7;
      String headerAuth = request.getHeader("Authorization");

      if (headerAuth != null && !headerAuth.isEmpty() && headerAuth.startsWith("Bearer ")) {
         return headerAuth.substring(jwtStart, headerAuth.length());
      }

      return null;
   }
}
