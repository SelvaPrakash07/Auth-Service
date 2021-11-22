package com.coherent.unnamed.auth.response;

import lombok.Data;

@Data
public class AuthBaseResponse {

    private static final long serialVersionUID = 1L;

    private int statusCode;

    private String statusMessage;

    private AuthResponse authResponse;
}
