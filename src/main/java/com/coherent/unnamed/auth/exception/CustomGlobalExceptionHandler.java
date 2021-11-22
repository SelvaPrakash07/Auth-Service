package com.coherent.unnamed.auth.exception;


import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@ControllerAdvice
public class CustomGlobalExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(AuthServiceException.class)
    public ResponseEntity<ErrorResponse> customHandleNotFound(AuthServiceException excep) {

        ErrorResponse errors = new ErrorResponse();
        errors.setStatusCode(excep.getStatusCode());
        errors.setStatusMessage(excep.getStatusMessage());

        return new ResponseEntity<>(errors, HttpStatus.OK);
    }
}
