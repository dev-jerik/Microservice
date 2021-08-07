package com.tutorial.api.config;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import lombok.extern.slf4j.Slf4j;

@RestControllerAdvice
@Slf4j
public class ApiExceptionHandler {
   @ExceptionHandler(AccessDeniedException.class)
   @ResponseStatus(HttpStatus.FORBIDDEN)
   protected void handleAccessDenied(AccessDeniedException e) {
      log.warn("ApiExceptionHandler: " + e.getMessage());
   }
}
