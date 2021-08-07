package com.tutorial.api.config;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class AuthenticationEntryPointConfig implements AuthenticationEntryPoint {
   private String activeProfile = "dev";

   @Override
   public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
         throws IOException, ServletException {

      /*
       * Shows the JWT error message if the system is running in a development mode, otherwise, show the authentication error message.
       */
      if (activeProfile.equals("dev")) {
         String jwtExceptionMessage = (String) request.getAttribute("jwtExceptionMessage");
         if (jwtExceptionMessage != null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, jwtExceptionMessage);
            return;
         }
      }
      log.error("Unauthorized error: " + authException.getMessage());
      response.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage());
   }
}