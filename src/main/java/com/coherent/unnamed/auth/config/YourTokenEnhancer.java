package com.coherent.unnamed.auth.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

@Configuration
public class YourTokenEnhancer extends JwtAccessTokenConverter{

	@Override
	public OAuth2AccessToken enhance(OAuth2AccessToken accessToken,
	                                 OAuth2Authentication authentication) {
	    DefaultOAuth2AccessToken customAccessToken = new DefaultOAuth2AccessToken(accessToken);

	    OAuth2AccessToken enhancedToken = super.enhance(customAccessToken, authentication);
	    return enhancedToken;
	}
	
}
