package com.githublogin.demo.model;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.time.Instant;

import static javax.persistence.FetchType.LAZY;
import static javax.persistence.GenerationType.IDENTITY;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "verificationtoken")
public class VerificationToken {
    @Id
    @GeneratedValue(strategy = IDENTITY)
    @Column(name = "token_id", unique = true,nullable = false)
    private Long id;
    
    @Column(name = "token")
    private String token;
    
    @OneToOne(fetch = LAZY)
    private User user;

    @Column(name = "exiryDate")
    private Instant expiryDate;
}
