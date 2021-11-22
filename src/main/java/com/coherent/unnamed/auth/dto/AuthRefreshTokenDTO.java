package com.coherent.unnamed.auth.dto;

import lombok.Data;

@Data
public class AuthRefreshTokenDTO {
	
	private String refreshToken;
	private Long userid;

}