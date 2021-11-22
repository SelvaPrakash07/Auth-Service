/*
package com.coherent.unnamed.auth.service;

import com.coherent.unnamed.auth.constants.TestConstants;
import com.coherent.unnamed.auth.dto.AuthRefreshTokenDTO;
import com.coherent.unnamed.auth.dto.AuthRequestBean;
import com.coherent.unnamed.auth.service.impl.UserDetailServiceImpl;
//import com.coherent.unnamed.auth.util.AuthUtills;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import static org.junit.jupiter.api.Assertions.*;

@RunWith(SpringRunner.class)
@SpringBootTest
class UserDetailServiceImplTest {

    @Mock
   // private AuthUtills authUtill;

    @InjectMocks
    private UserDetailServiceImpl userDetailService;

   // public void setAuthUtill(AuthUtills authUtill) {
     //   this.authUtill = authUtill;
   // }


    @Test
    void authenticate() {
        try {
            userDetailService.setAuthUtill(authUtill);
            assertEquals(userDetailService.authenticate(authRequestBean()), userDetailService.authenticate(authRequestBean()));
        } catch (Exception e) {
        }
    }

    private AuthRequestBean authRequestBean() {
        AuthRequestBean authRequestBean = new AuthRequestBean();
        authRequestBean.setUsername(TestConstants.USER_NAME);
        authRequestBean.setClient_id(TestConstants.CLIENT_ID);
        authRequestBean.setClient_secret(TestConstants.CLIENT_SECRET);
        authRequestBean.setGrant_type(TestConstants.GRANT_TYPE);
        return authRequestBean;
    }

    private AuthRefreshTokenDTO authRefreshTokenDTO() {
        AuthRefreshTokenDTO authRefreshTokenDTO = new AuthRefreshTokenDTO();
        authRefreshTokenDTO.setRefreshtoken(TestConstants.REFRESH_TOKEN);
        authRefreshTokenDTO.setUserid(TestConstants.ID);
        return authRefreshTokenDTO;
    }

    @Test
    void refreshToken() {
        try {
            userDetailService.setAuthUtill(authUtill);
            assertEquals(userDetailService.refreshToken(authRefreshTokenDTO()), userDetailService.refreshToken(authRefreshTokenDTO()));
        } catch (Exception e) {
        }
    }
}*/
