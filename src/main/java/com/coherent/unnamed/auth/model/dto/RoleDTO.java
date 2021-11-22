package com.coherent.unnamed.auth.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.io.Serializable;

@Data
public class RoleDTO implements Serializable {

    private static final long serialVersionUID = 7545340461305338564L;

    @JsonProperty("id")
    private long id;

	@JsonProperty("name")
    private String name;

	@JsonProperty("description")
    private String description;

	@JsonProperty("isActive")
    private Boolean isActive;

    @JsonProperty("level")
    private int level;
}
