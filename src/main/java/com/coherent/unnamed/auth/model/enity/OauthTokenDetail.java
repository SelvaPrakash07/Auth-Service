package com.coherent.unnamed.auth.model.enity;

import com.coherent.unnamed.auth.constant.Constants;
import lombok.Data;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Date;

@Data
@Entity
@Table(name = "oauth_token_detail")
public class OauthTokenDetail implements Serializable{
	/**
	 * 
	 */

	private static final long serialVersionUID = 1L;

	@Id
	@Column(name = Constants.ID)
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private long id;
	
	@Column(name = Constants.ACCESS_TOKEN)
	private String accessToken;
	
	@Column(name = Constants.REFRESH_TOKEN)
	private String refreshToken;
	
	@Column(name = Constants.USER_ID_FK)
	private Long userIdFk;
	
	@Column(name = Constants.TOT_ATTEMPT)
	private Integer totAttempt;

	@Column(name = "deleted_flag")
	private Integer deletedFlag;

	@Column(name = Constants.CREATED_AT)
	private Date createdAt;
	
	@Column(name = Constants.UPDATED_AT)
	private Date updatedAt;
	
	public OauthTokenDetail(){}

	public OauthTokenDetail(long id, String accessToken, String refreshToken, Long userIdFk, Integer totAttempt,
			Date createdAt, Date updatedAt) {
		super();
		this.id = id;
		this.accessToken = accessToken;
		this.refreshToken = refreshToken;
		this.userIdFk = userIdFk;
		this.totAttempt = totAttempt;
		this.createdAt = createdAt;
		this.updatedAt = updatedAt;
	}
	
	

}
