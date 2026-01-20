package com.wso2.wso2.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.net.URI;
import java.time.Instant;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(AuthenticationException.class)
    public ProblemDetail handleAuthenticationException(AuthenticationException ex) {
        String detail = ex.getMessage();

        // Check if the error message contains 'expired'
        if (detail.toLowerCase().contains("expired")) {
            detail = "Your session has expired. Please refresh your token.";
        }

        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, detail);
        problemDetail.setTitle("Authentication Failure");
        return problemDetail;
    }


//    // Handles 401 Unauthorized (Invalid/Missing Token)
//    @ExceptionHandler(AuthenticationException.class)
//    public ProblemDetail handleAuthenticationException(AuthenticationException ex) {
//        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, ex.getMessage());
//        problemDetail.setTitle("Authentication Required");
//        problemDetail.setType(URI.create("https://api.yoursite.com"));
//        problemDetail.setProperty("timestamp", Instant.now());
//        return problemDetail;
//    }

    // Handles 403 Forbidden (Missing Roles)
    @ExceptionHandler(AccessDeniedException.class)
    public ProblemDetail handleAccessDeniedException(AccessDeniedException ex) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, "You do not have the required 'admin' role.");
        problemDetail.setTitle("Access Denied");
        problemDetail.setType(URI.create("https://api.yoursite.com"));
        problemDetail.setProperty("timestamp", Instant.now());
        return problemDetail;
    }
}
