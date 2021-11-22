package com.coherent.unnamed.auth.model.dto;

import com.coherent.unnamed.auth.model.enity.UserRole;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.coherent.unnamed.auth.model.enity.Country;
import com.coherent.unnamed.auth.model.enity.Region;
import com.coherent.unnamed.auth.model.enity.Role;
import lombok.Data;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.List;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class UserDTO implements Serializable {

	private static final long serialVersionUID = 7545340461305338564L;
	private long id;
	private String fullName;
	private String email;
	private Integer isActive;




	
}
