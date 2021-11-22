package com.coherent.unnamed.auth.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

@RequiredArgsConstructor
@Getter
@Setter
public class AuthServiceException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private int statusCode;

    private String statusMessage;

    public AuthServiceException(int statusCode, String statusMessage) {
        this.statusCode = statusCode;
        this.statusMessage = statusMessage;
    }

}
