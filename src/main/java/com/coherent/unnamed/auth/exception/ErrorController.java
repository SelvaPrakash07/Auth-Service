package com.coherent.unnamed.auth.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/error")
public class ErrorController implements org.springframework.boot.web.servlet.error.ErrorController {

    @Override
    public String getErrorPath() {
        return "/error";
    }

    @RequestMapping
    public ResponseEntity<ErrorResponse> error(HttpServletRequest aRequest, HttpServletResponse response,
                                               int errorCode, String errorMessage) {
        ErrorResponse errorResponse = new ErrorResponse();
        errorResponse.setStatusCode(errorCode);
        errorResponse.setStatusMessage(errorMessage);

        return new ResponseEntity<ErrorResponse>(errorResponse, HttpStatus.OK);
    }

}
