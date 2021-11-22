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
package com.coherent.unnamed.auth.controller;

import java.io.IOException;
import java.util.Map;

import com.coherent.unnamed.auth.dto.AuthRefreshTokenDTO;
import com.coherent.unnamed.auth.dto.AuthRequestBean;
import com.coherent.unnamed.auth.model.dto.MailDTO;
import com.coherent.unnamed.auth.model.dto.UserDTO;
import com.coherent.unnamed.auth.response.AuthBaseResponse;
import com.coherent.unnamed.auth.response.AuthResponse;
import com.coherent.unnamed.auth.response.BaseResponse;
import com.coherent.unnamed.auth.response.SuccessResponse;
import com.coherent.unnamed.auth.service.UserDetailService;
import com.coherent.unnamed.auth.util.OauthUtills;
import org.codehaus.jackson.map.ObjectMapper;
import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Class - OauthController
 * Class OauthController of Authorization Service
 * 
 * @category public
 * @author
 * @type Class
 * @data Sep 22 2021
 */

@RestController
@RequestMapping("/unnamed-auth-service/user")
public class OauthController {

    private static final Logger LOGGER = LoggerFactory.getLogger(OauthController.class);

    public static final String RESPONSE = "response";
    public static final String STATUS = "status";

    /**
	 * The userDetailService
	 * of type UserDetailService
	 */
    @Autowired
    private UserDetailService userDetailService;

    public ObjectMapper mapper = new ObjectMapper();
    /**
	 * The modelMapper
	 * of type ModelMapper
	 */
    ModelMapper modelMapper = new ModelMapper();
    
    @PostMapping("/login")
        public BaseResponse login(@RequestBody MailDTO mailDTO){
            String response = userDetailService.generateOTP(mailDTO);
            BaseResponse baseResponse = new BaseResponse();
            baseResponse.setData(response);
            return baseResponse;
        }

    @PostMapping("/resendotp")
    public BaseResponse resendotp(@RequestBody MailDTO mailDTO){
        String response = userDetailService.resendOTP(mailDTO);
        BaseResponse baseResponse = new BaseResponse();
        baseResponse.setData(response);
        return baseResponse;
    }

    /**
     * Method - authenticate
     *
     * @param requestBean
     * @return
     */

    @PostMapping(value = "/verifyotp", produces = MediaType.APPLICATION_JSON_VALUE)
    public SuccessResponse authenticate(@RequestBody AuthRequestBean requestBean) {
        SuccessResponse successResponse = new SuccessResponse();
        LOGGER.info("Welcome to authenticate() in OauthController :: Request Body :: " + requestBean.toString());
        AuthBaseResponse authResponse = userDetailService.authenticate(requestBean);
        successResponse.setData(authResponse);
        return successResponse;
    }

    /**
     * Method - refreshToken
     *
     //	 * @param authRefreshTokenDto
     * @return
     */
  @PostMapping(value = "/refreshToken", produces = MediaType.APPLICATION_JSON_VALUE)
  public SuccessResponse refreshToken(@RequestBody AuthRefreshTokenDTO authRefreshTokenDto) {
        SuccessResponse successResponse = new SuccessResponse();
        LOGGER.info("Welcome to refreshToken() in OauthController :: ");
        AuthResponse authResponse = userDetailService.refreshToken(authRefreshTokenDto);
        successResponse.setData(authResponse);
        return successResponse;
    }
}

