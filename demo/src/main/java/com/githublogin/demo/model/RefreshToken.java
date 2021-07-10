package com.githublogin.demo.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

//import javax.persistence.*;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import java.time.Instant;


@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "refreshtoken_id" ,unique = true)
    private Long Id;

    @Column
    private String token;

    @Column(name="creatd_Date")
    private Instant createdDate;
}
