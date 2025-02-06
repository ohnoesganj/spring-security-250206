package com.example.security.global.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.MappedSuperclass;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@MappedSuperclass
@NoArgsConstructor
@AllArgsConstructor
@Getter
@EntityListeners(AuditingEntityListener.class)
public class BaseTime extends BaseEntity {
    @CreatedDate
    @Setter(AccessLevel.PRIVATE)
    @JsonProperty("createdAt")
    private LocalDateTime createdDate;

    @LastModifiedDate
    @Setter(AccessLevel.PRIVATE)
    @JsonProperty("modifiedAt")
    private LocalDateTime modifiedDate;
}
