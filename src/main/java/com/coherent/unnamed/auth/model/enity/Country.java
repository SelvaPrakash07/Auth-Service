package com.coherent.unnamed.auth.model.enity;

import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import javax.persistence.*;
import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "master_country")
public class Country {
    /**
     *
     */
    private static final long serialVersionUID = -4227846222822402384L;
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", updatable = false, nullable = false)
    private Long id;

    @Column(name = "country_name")
    private String name;

    @OneToOne
    @JoinColumn(name = "master_entity_id_fk")
    private MasterEntity masterEntity;

    @OneToOne
    @JoinColumn(name = "master_region_id_fk")
    private Region region;

    @Column(name = "country_code")
    private String countryCode;

    @Column(name = "is_active")
    private Integer isActive;

    @Column(name = "deleted_flag")
    private Integer deletedFlag;

    @Column(name = "created_by")
    private Integer createdBy;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "modified_at")
    private LocalDateTime modifiedAt;

    @Column(name = "modified_by")
    private Integer modifiedBy;
}
