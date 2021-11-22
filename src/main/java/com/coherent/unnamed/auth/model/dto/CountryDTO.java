package com.coherent.unnamed.auth.model.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CountryDTO {

    private Long id;

    private String name;

    private String countryCode;

    private Integer isActive = 1;

    private Integer deletedFlag = 0;

    private Long createdBy;

    private Long modifiedBy;

    private RegionDTO region;
}
