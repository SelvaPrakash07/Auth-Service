package com.coherent.unnamed.auth.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BaseResponse {

    @Builder.Default
    private int statusCode = 200;

    @Builder.Default
    private String statusMessage = "Success";

    private Object data;


}
