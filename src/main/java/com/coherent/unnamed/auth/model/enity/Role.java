package com.coherent.unnamed.auth.model.enity;

import lombok.Data;
import org.hibernate.annotations.ColumnDefault;

import javax.persistence.*;
import java.io.Serializable;
import java.sql.Timestamp;

@Data
@Entity
/*
@SQLDelete(sql = "")
*/
@Table(name = "master_role")
public class Role implements Serializable {
    /**
     *
     */
    private static final long serialVersionUID = -4227846222822402384L;
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", updatable = false, nullable = false)
    private Integer id;

    @Column(name = "role_name")
    private String name;

    @Column(name = "role_desc")
    private String description;

    @OneToOne
    @JoinColumn(name = "master_entity_id_fk")
    private MasterEntity masterEntity;

    @ColumnDefault("1")
    @Column(name = "is_active")
    private Integer isActive;

    @ColumnDefault("0")
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
