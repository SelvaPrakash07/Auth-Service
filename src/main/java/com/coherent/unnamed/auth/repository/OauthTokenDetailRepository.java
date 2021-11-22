package com.coherent.unnamed.auth.repository;

import java.util.List;


import com.coherent.unnamed.auth.model.enity.OauthTokenDetail;
import com.coherent.unnamed.auth.model.enity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;



@Repository
public interface OauthTokenDetailRepository extends JpaRepository<OauthTokenDetail, Long> {



/*	List<OauthTokenDetail> getTokenDetailByUserIdFk(Long userid);*/
@Query("Select tokenDet from OauthTokenDetail tokenDet where tokenDet.userIdFk=:userIdFk order by tokenDet.id desc")
public List<OauthTokenDetail> getTokenDetailByUserId(@Param(value = "userIdFk") long userIdFk);
	/*List<OauthTokenDetail> getTokenDetailByUserId(Long userid);*/

	List<OauthTokenDetail> findFirstByUserIdFkOrderByCreatedAtDesc(long userId);






/*	List<OauthTokenDetail> getTokenDetailByUserIdFk(User user);*/
}