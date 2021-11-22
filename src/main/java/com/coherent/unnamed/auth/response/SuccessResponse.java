package com.coherent.unnamed.auth.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.ToString;

import java.io.Serializable;

@Data
@ToString
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SuccessResponse<T> implements Serializable {

    private static final long serialVersionUID = 5926468583005150707L;
    private int statusCode = 200;
    private T data;
    private String statusMessage = "Success";


}
