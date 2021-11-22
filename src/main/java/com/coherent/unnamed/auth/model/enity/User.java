package com.coherent.unnamed.auth.model.enity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.sun.istack.NotNull;
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.*;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;


@Data
@Entity
/*
@SQLDelete(sql = "")
*/
@Table(name = "users")
public class User implements Serializable{
    /**
     *
     */
    private static final long serialVersionUID = -4227846222822402384L;
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", updatable = false, nullable = false)
    private Long id;

    @Column(name = "fullname")
    private String fullName;

    @Column(name = "email_id")
    private String email;

    @Column(name = "otp")
    private Integer otp;

    @OneToMany(mappedBy = "user")
    private List<UserRole> roles;

    @Column(name = "is_active")
    private Integer isActive;

    @Column(name = "deleted_flag")
    private Integer deletedFlag;

    @Column(name = "created_by")
    private Long createdBy;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "modified_at")
    private LocalDateTime modifiedAt;

    @Column(name = "modified_by")
    private Long modifiedBy;



    public boolean isEnabled() {
        if (this.isActive == null || this.isActive != 0) {
            return false;
        }
        return true;
    }


    @Transient
    @JsonIgnore
    public Set<GrantedAuthority> getAuthorities() {
        Set<GrantedAuthority> authorities = new LinkedHashSet<>();
        authorities.addAll((Collection<? extends GrantedAuthority>) roles.get(0).getRole());
        return authorities;
    }

}
