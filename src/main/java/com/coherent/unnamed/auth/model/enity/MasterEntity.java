package com.coherent.unnamed.auth.model.enity;

import lombok.Data;

import javax.persistence.*;
import java.io.Serializable;
import java.sql.Timestamp;

@Data
@Entity
/*
@SQLDelete(sql = "")
*/
@Table(name = "master_entity")
public class MasterEntity implements Serializable {
    /**
     *
     */
    private static final long serialVersionUID = -4227846222822402384L;
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", updatable = false, nullable = false)
    private Integer id;

    @Column(name = "entity_code")
    private String entityCode;

    @Column(name = "entity_name")
    private String entityName;

    @Column(name = "is_active")
    private Integer isActive;

    @Column(name = "deleted_flag")
    private Integer deletedFlag;

    @Column(name = "created_by")
    private Integer createdBy;

    @Column(name = "created_at")
    private Timestamp createdAt;

    @Column(name = "modified_at")
    private Timestamp modifiedAt;

    @Column(name = "modified_by")
    private Integer modifiedBy;
}
