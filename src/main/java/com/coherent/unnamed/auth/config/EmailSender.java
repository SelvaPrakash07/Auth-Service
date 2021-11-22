
package com.coherent.unnamed.auth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.stereotype.Component;

import java.util.Properties;

@Component
@Configuration
public class EmailSender {

    @Value("${app.mail.username}")
    private String UserName;

    @Value("${app.mail.port}")
    private int port;

    @Value("${app.mail.password}")
    private String password;

    @Value("${app.mail.host}")
    private  String mailHost;

    @Bean
    public JavaMailSenderImpl mailSender() {
        JavaMailSenderImpl javaMailSender = new JavaMailSenderImpl();
        javaMailSender.setHost(mailHost);
        javaMailSender.setPort(port);
        javaMailSender.setUsername(UserName);
        javaMailSender.setPassword(password);
        Properties properties = javaMailSender.getJavaMailProperties();
        properties.put("mail.transport.protocol", "smtp");
        properties.put("mail.smtp.auth","true");
        properties.put("mail.smtp.starttls.enable","true");
        properties.put("mail.debug","true");
        return  javaMailSender;
    }
}

