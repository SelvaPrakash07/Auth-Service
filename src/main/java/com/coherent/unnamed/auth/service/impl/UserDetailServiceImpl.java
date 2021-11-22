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

package com.coherent.unnamed.auth.service.impl;

import com.coherent.unnamed.auth.constant.Constants;
import com.coherent.unnamed.auth.dto.AuthRefreshTokenDTO;
import com.coherent.unnamed.auth.dto.AuthRequestBean;
import com.coherent.unnamed.auth.exception.AuthServiceException;
import com.coherent.unnamed.auth.model.dto.MailDTO;
import com.coherent.unnamed.auth.model.enity.User;
import com.coherent.unnamed.auth.repository.UserRepository;
import com.coherent.unnamed.auth.response.AuthBaseResponse;
import com.coherent.unnamed.auth.response.AuthResponse;
import com.coherent.unnamed.auth.util.AuthUtills;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import com.coherent.unnamed.auth.service.UserDetailService;

import javax.transaction.Transactional;
import java.util.Optional;
import java.util.Random;

/**
 * Class - UserDetailServiceImpl
 * Class UserDetailServiceImpl of Authorization Service
 * 
 * @category public
 * @author
 * @type Class
 * @data Sep 22 2021
 */
@Service
@Transactional
public class UserDetailServiceImpl implements UserDetailService {

	/**
	 * The authUtill
	 * of type AuthUtills
	 */
    @Autowired
    private AuthUtills authUtill;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JavaMailSender javaMailSender;


    public void setAuthUtill(AuthUtills authUtill) {
        this.authUtill = authUtill;
    }

    /* (non-Javadoc)
	 * @see com.olam.fsp.authorization.origin.
	 * service.UserDetailService#authenticate(
	 * com.olam.fsp.cache.AuthRequestBean)
	 */
    @Override
    public AuthBaseResponse authenticate(AuthRequestBean requestBean) {
        return authUtill.authenticate(requestBean);
    }
    
     /*(non-Javadoc)
	 * @see com.olam.fsp.authorization.origin.
	 * service.UserDetailService#refreshToken(
	 * com.olam.fsp.cache.AuthRefreshTokenDTO)
	 */

    @Override
    public AuthResponse refreshToken(AuthRefreshTokenDTO authRefreshTokenDto){
        return authUtill.refreshToken(authRefreshTokenDto);
    }

    @Override
    public String generateOTP(MailDTO mailDTO) {
        Optional<User> user = userRepository.findByEmail(mailDTO.getEmail());
        if (user.isPresent()) {
            Random random = new Random();
            int OTP = 1000 + random.nextInt(9000);
            SimpleMailMessage simpleMailMessage = new SimpleMailMessage();
            simpleMailMessage.setFrom(Constants.MAILID);
            simpleMailMessage.setTo(mailDTO.getEmail());
            simpleMailMessage.setSubject(Constants.OTP_MSG);
            simpleMailMessage.setText(Constants.MAIL_OTP_MSG + OTP );
            user.get().setOtp(OTP);
            userRepository.save(user.get());
            javaMailSender.send(simpleMailMessage);
        } else
        {
            throw new AuthServiceException(Constants.ERROR_CODE,Constants.INVALID) ;
        }
        return Constants.SUCCESS;
    }

    @Override
    public String resendOTP(MailDTO mailDTO) {
        try{
            Optional<User> user = userRepository.findByEmail(mailDTO.getEmail());
            if (user.isPresent()) {
                Random random = new Random();
                int OTP = 1000 + random.nextInt(9000);
                SimpleMailMessage simpleMailMessage = new SimpleMailMessage();
                simpleMailMessage.setFrom(Constants.MAILID);
                simpleMailMessage.setTo(mailDTO.getEmail());
                simpleMailMessage.setSubject(Constants.OTP_MSG);
                simpleMailMessage.setText(Constants.MAIL_OTP_MSG+ OTP );
                user.get().setOtp(OTP);
                userRepository.save(user.get());
                javaMailSender.send(simpleMailMessage);
            } else
                {
                    throw new AuthServiceException(Constants.ERROR_CODE,Constants.INVALID) ;
                }
            } catch (MailException e) {
                e.printStackTrace();
            }
            return Constants.SUCCESS1;
        }






}
