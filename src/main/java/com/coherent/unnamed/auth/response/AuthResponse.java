package com.coherent.unnamed.auth.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthResponse {

    private String accessToken;

    private String refreshToken;

    private String tokenType;

    private String currentAttempt;

}
