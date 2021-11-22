package com.coherent.unnamed.auth.config;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.util.FileCopyUtils;


@Configuration
@EnableAuthorizationServer
public class OAuthConfiguration extends AuthorizationServerConfigurerAdapter{

	 @Value("${app.oauth-private-key}")
	 private String privateKey;
	  
	  @Value("${app.oauth-public-key}")
	  private String publicKey;
	  
	  @Autowired
	  private AuthenticationManager authenticationManager;
	  
	  @Override
	  public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
		  TokenEnhancerChain enhancerChain = new TokenEnhancerChain();
	      endpoints.tokenStore(tokenStore())
	      		   .tokenEnhancer(enhancerChain)
	      		   .authenticationManager(authenticationManager)
	        	   .accessTokenConverter(accessTokenConverter());
	  }
	  
	  
	 
	  
	  @Override
	  public void configure(final AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
	    oauthServer.tokenKeyAccess("permitAll()");
	  }
	  
	  @Override
	  public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
	    clients.inMemory()
	      //.withClient("clientId").secret("$2a$10$vCXMWCn7fDZWOcLnIEhmK.74dvK1Eh8ae2WrWlhr2ETPLoxQctN4.")
	      .withClient("clientId").secret(new BCryptPasswordEncoder().encode("secret"))
	      .authorizedGrantTypes("password", "authorization_code", "refresh_token")
	      .scopes("read","write")
	      .autoApprove(true);
	  }
	  
	  
	  //http://localhost:8080/auth/token?username=dbUsername&password=DbPassword  and header username=clientId and password=password
	  

	  
		@Bean
		public TokenStore tokenStore() {
			return new JwtTokenStore(accessTokenConverter());
		}
	
		@Bean
		public JwtAccessTokenConverter accessTokenConverter() {

		    final JwtAccessTokenConverter converter = new YourTokenEnhancer();
			final KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(new ClassPathResource("mytest.jks"),
					"mypass".toCharArray());
			converter.setKeyPair(keyStoreKeyFactory.getKeyPair("mytest"));
			converter.setSigningKey(getPrivateAsString());
			converter.setVerifierKey(getPublicAsString());
			return converter;
			
		}
		
				
		@Bean
		public BCryptPasswordEncoder encoder() {
			return new BCryptPasswordEncoder();
		}
		

		private String getPublicAsString() {
	        try {
	        	
	        	Resource resource = new ClassPathResource(publicKey);
				byte[] bdata = FileCopyUtils.copyToByteArray(resource.getInputStream());
				return new String(bdata, StandardCharsets.UTF_8);
				
	        } catch (IOException e) {
	            throw new RuntimeException(e);
	        }
	    }
		
		private String getPrivateAsString() {
	        try {
	        	
	        	Resource resource = new ClassPathResource(privateKey);
				byte[] bdata = FileCopyUtils.copyToByteArray(resource.getInputStream());
				return new String(bdata, StandardCharsets.UTF_8);
				
	        } catch (IOException e) {
	            throw new RuntimeException(e);
	        }
	    }
		
	
}
