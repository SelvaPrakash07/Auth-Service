package com.coherent.unnamed.auth.model.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

import java.io.Serializable;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class MailDTO implements Serializable {

    private static final long serialVersionUID = 7545340461305338564L;

    private long id;
    private String fullName;
    private String email;
    private int otp;
}