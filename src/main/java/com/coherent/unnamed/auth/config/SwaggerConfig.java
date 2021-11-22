/*
 *
 * Copyright (c) 2019 Coherent Limited
 *
 * All information contained herein is, and remains the property of Coherent
 * Limited. The intellectual and technical concepts contained herein are
 * proprietary to Coherent and are protected by logic secret or copyright law.
 * Dissemination of this information or reproduction of this material is
 * strictly forbidden unless prior written permission is obtained from Coherent
 * Limited
 *
 */
package com.coherent.unnamed.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.RequestMethod;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.builders.ResponseMessageBuilder;
import springfox.documentation.schema.ModelRef;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.ApiKey;
import springfox.documentation.service.SecurityScheme;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import java.util.ArrayList;
import java.util.List;

import static com.google.common.collect.Lists.newArrayList;

@Configuration
@EnableSwagger2
public class SwaggerConfig {

    @Bean
    public Docket userManagementAPI() {
        List<SecurityScheme> schemeList = new ArrayList<>();
        schemeList.add(new ApiKey("Bearer", "Authorization", "header"));
        return new Docket(DocumentationType.SWAGGER_2).apiInfo(userApiInfo()).securitySchemes(schemeList).select()
                .apis(RequestHandlerSelectors.basePackage("com.coherent.unnamed.auth.controller"))
                .paths(PathSelectors.ant("/**/*")).build().useDefaultResponseMessages(false)
                .globalResponseMessage(RequestMethod.GET,
                        newArrayList(
                                new ResponseMessageBuilder().code(500).message("500 message")
                                        .responseModel(new ModelRef("Error")).build(),
                                new ResponseMessageBuilder().code(403).message("Forbidden!!!!!").build()));

    }

    private ApiInfo userApiInfo() {
        return new ApiInfoBuilder().title("unnamed Auth Service Management API")
                .description("This page lists all the rest apis for Auth Service Management").version("1.0-SNAPSHOT").build();
    }
}
