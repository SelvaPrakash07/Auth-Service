package com.coherent.unnamed.auth.model.enity;

import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import javax.persistence.*;
import java.io.Serializable;
import java.time.LocalDateTime;

@Data
@Entity
/*
@SQLDelete(sql = "")
*/
@Table(name = "master_region")
public class Region implements Serializable {
    /**
     *
     */
    private static final long serialVersionUID = -4227846222822402384L;
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", updatable = false, nullable = false)
    private Long id;

    @Column(name = "region_name")
    private String name;

    @OneToOne
    @JoinColumn(name = "master_entity_id_fk")
    private MasterEntity masterEntity;

    @Column(name = "region_desc")
    private String description;

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
}
