/*******************************************************************************
 *
 * Copyright (c) 2018 OLAM Limited
 *
 * All information contained herein is, and remains the property of OLAM
 * Limited. The intellectual and technical concepts contained herein are
 * proprietary to OLAM and are protected by logic secret or copyright law.
 * Dissemination of this information or reproduction of this material is
 * strictly forbidden unless prior written permission is obtained from OLAM
 * Limited
 *
 *******************************************************************************/
package com.coherent.unnamed.auth.service;

import com.coherent.unnamed.auth.dto.AuthRefreshTokenDTO;
import com.coherent.unnamed.auth.dto.AuthRequestBean;
import com.coherent.unnamed.auth.model.dto.MailDTO;
import com.coherent.unnamed.auth.response.AuthBaseResponse;
import com.coherent.unnamed.auth.response.AuthResponse;

/**
 * Class - UserDetailService 
 * Class UserDetailService of Authorization Service
 *
 * @author
 * @date Sep 22 2021
 */
public interface UserDetailService {
	
	/**
	 * Method - authenticate
	 *
	 * @param requestBean
	 */
	AuthBaseResponse authenticate(AuthRequestBean requestBean);
    
	/**
	 * Method - refreshToken
	 *
	// * @param authRefreshTokenDto
	 */
AuthResponse refreshToken(AuthRefreshTokenDTO authRefreshTokenDto);

	String generateOTP(MailDTO mailDTO);

	String resendOTP(MailDTO mailDTO);
}
