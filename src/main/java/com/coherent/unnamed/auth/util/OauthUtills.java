package com.coherent.unnamed.auth.util;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.annotation.PostConstruct;

import com.coherent.unnamed.auth.exception.AuthServiceException;
import com.coherent.unnamed.auth.exception.ErrorCode;
import com.coherent.unnamed.auth.model.dto.UserDTO;
import com.coherent.unnamed.auth.constant.Constants;
import com.coherent.unnamed.auth.model.enity.OauthTokenDetail;
import com.coherent.unnamed.auth.model.enity.User;
import com.coherent.unnamed.auth.repository.OauthTokenDetailRepository;
import com.coherent.unnamed.auth.repository.UserRepository;
import com.coherent.unnamed.auth.response.AuthResponse;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.FileCopyUtils;

import com.fasterxml.jackson.databind.ObjectMapper;


import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Service
public class OauthUtills {

    private static final Logger LOG = LoggerFactory.getLogger(OauthUtills.class);

    @Value("${app.subject}")
    private String subject;

    @Value("${app.issuer}")
    private String issuer;

    private RSAPrivateKey pk;

    private int tokenExpiryMins = 60;

    public OauthUtills() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    @PostConstruct
    public void init() {
        try {
            Resource resource = new ClassPathResource(Constants.OAUTH);
            byte[] bdata = FileCopyUtils.copyToByteArray(resource.getInputStream());
            String privateKey = new String(bdata, StandardCharsets.UTF_8);
            byte[] keyBytes = org.apache.commons.codec.binary.Base64.decodeBase64(privateKey);
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance(Constants.OAUTH_ALGO_NAME, BouncyCastleProvider.PROVIDER_NAME);
            this.pk = (RSAPrivateKey) kf.generatePrivate(privateKeySpec);
        } catch (Exception e) {
            LOG.error("Exception occured while loading oauth utills", e);
        }
    }

    public AuthResponse jwtTokenGenerator(User user, Map<String, Object> responseMap, UserRepository userRepository, OauthTokenDetailRepository oauthTokenDetRepository, boolean loginFlag) throws NoSuchAlgorithmException, NoSuchProviderException {

        UserDTO userDto = new UserDTO();
        userDto.setId(user.getId());
        userDto.setFullName(user.getFullName());
        userDto.setIsActive(user.getIsActive());
        userDto.setEmail(user.getEmail());

        if (userDto != null) {

            Map<String, Object> userInfo = new ObjectMapper().convertValue(userDto, Map.class);

            //We will sign our JWT with our ApiKey secret
            SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RS256;

            long expDate = System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(tokenExpiryMins);

            userInfo.put(Constants.TOKEN_EXPIRE_AT_STR, expDate);

            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

            //Let's set the JWT Claims
            JwtBuilder builder = Jwts.builder()
                    .setClaims(userInfo)
                    .setHeaderParam("typ", "JWT")
                    .setId(String.valueOf(user.getId()))
                    .setExpiration(new Date(expDate))
                    .setIssuedAt(new Date())
                    .setSubject(subject)
                    .setIssuer(issuer)
                    .signWith(signatureAlgorithm, pk);

            String accessToken = builder.compact();

            JwtBuilder jwtRefreshBuilder = Jwts.builder()
                    .setId(String.valueOf(user.getId()))
                    .setHeaderParam("typ", "JWT")
                    .setSubject(subject)
                    .setExpiration(Date.from(ZonedDateTime.now().plusMonths(2).toInstant()))
                    .setIssuedAt(new Date())
                    .setIssuer(issuer)
                    .signWith(signatureAlgorithm, pk);

            String jwtRefreshToken = jwtRefreshBuilder.compact();

            boolean vFlag = saveOrUpdateToken(user.getId(), accessToken, jwtRefreshToken, oauthTokenDetRepository, userRepository, loginFlag);

            int curAttempt = 0;

            if (vFlag) {
                AuthResponse authResponse = new AuthResponse();
                authResponse.setTokenType("Bearer");
                authResponse.setCurrentAttempt("The has " + (5 - curAttempt) + " remaining attempts to login into the system ");
                authResponse.setAccessToken(accessToken);
                authResponse.setRefreshToken(jwtRefreshToken);
                return authResponse;
            }

            else {
                throw new AuthServiceException(HttpStatus.LOCKED.value(), ErrorCode.CAP_1003.getMessage());
            }
        }
        else {

            throw new AuthServiceException(HttpStatus.UNAUTHORIZED.value(), ErrorCode.CAP_1004.getMessage());
        }
    }


    private boolean saveOrUpdateToken(long userId, String accessToken, String jwtRefreshToken, OauthTokenDetailRepository oauthTokenDetRepository, UserRepository userRepository, boolean loginFlag) {


        OauthTokenDetail oauthtokenDet = null;

        boolean bflag = false;

        List<OauthTokenDetail> extTokenDetList = oauthTokenDetRepository.findFirstByUserIdFkOrderByCreatedAtDesc(userId);

        if (extTokenDetList != null && extTokenDetList.size() > 0) {

            LOG.info("Last record count for the given user::" + extTokenDetList.size());

            for (OauthTokenDetail tokenDet : extTokenDetList) {
                int totAttempt = tokenDet.getTotAttempt() != null ? tokenDet.getTotAttempt() : 0;
                long diffMinutes = (new Date().getTime() - tokenDet.getCreatedAt().getTime()) / (60 * 1000);

                if (diffMinutes < tokenExpiryMins) {

                    if (totAttempt < 5) {

                        oauthtokenDet = new OauthTokenDetail();
                        totAttempt = loginFlag ? totAttempt += 1 : totAttempt;
                        oauthtokenDet.setId(tokenDet.getId());
                        oauthtokenDet.setAccessToken(accessToken);
                        oauthtokenDet.setRefreshToken(jwtRefreshToken);
                        oauthtokenDet.setUserIdFk(userId);
                        oauthtokenDet.setTotAttempt(1);
                        oauthtokenDet.setDeletedFlag(1);
                        oauthtokenDet.setCreatedAt(tokenDet.getCreatedAt());
                        oauthtokenDet.setUpdatedAt(new Date());

                        oauthTokenDetRepository.save(oauthtokenDet);
                        bflag = true;

                    } else {
                        /*  userRepository.updateBlockUser(userId);
                        bflag = false;*/
                    }
                } else {

                    oauthtokenDet = new OauthTokenDetail();
                    oauthtokenDet.setAccessToken(accessToken);
                    oauthtokenDet.setRefreshToken(jwtRefreshToken);
                    oauthtokenDet.setUserIdFk(userId);
                    oauthtokenDet.setTotAttempt(1);
                    oauthtokenDet.setDeletedFlag(1);
                    oauthtokenDet.setCreatedAt(new Date());
                    oauthtokenDet.setUpdatedAt(new Date());

                    oauthTokenDetRepository.save(oauthtokenDet);
                    bflag = true;
                }
            }
        } else {

            oauthtokenDet = new OauthTokenDetail();
            oauthtokenDet.setAccessToken(accessToken);
            oauthtokenDet.setRefreshToken(jwtRefreshToken);
            oauthtokenDet.setUserIdFk(userId);
            oauthtokenDet.setTotAttempt(1);
            oauthtokenDet.setDeletedFlag(1);
            oauthtokenDet.setCreatedAt(new Date());
            oauthtokenDet.setUpdatedAt(new Date());

            oauthTokenDetRepository.save(oauthtokenDet);
            bflag = true;
        }
        return bflag;
    }
}
