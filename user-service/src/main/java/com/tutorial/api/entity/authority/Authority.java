package com.tutorial.api.entity.authority;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

import org.springframework.security.core.GrantedAuthority;

import com.tutorial.api.entity.role.Role;

import lombok.Data;
import lombok.EqualsAndHashCode;

@Entity
@Table(name = "authority")
@Data
@EqualsAndHashCode(callSuper = false, onlyExplicitlyIncluded = true)
public class Authority implements GrantedAuthority {
   /**
    * 
    */
   private static final long serialVersionUID = 1L;

   @Id
   @GeneratedValue(strategy = GenerationType.IDENTITY)
   @EqualsAndHashCode.Include
   private long id;

   @Column(name = "code")
   private String code;

   @Column(name = "description")
   private String description;

   @ManyToOne
   private Role role;

   @Override
   public String getAuthority() {
      return code;
   }

}
