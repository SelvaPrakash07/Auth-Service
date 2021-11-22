package com.coherent.unnamed.auth.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Data;

@JsonIgnoreProperties(ignoreUnknown = true)
@Data
public class AuthRequestBean {

	private String email;
	private Integer otp;


}
