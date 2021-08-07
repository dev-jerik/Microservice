package com.tutorial.api.entity.user;

import java.util.Set;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.Table;

import com.tutorial.api.entity.role.Role;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Entity
@Table(name = "user")
@Data
@AllArgsConstructor
@NoArgsConstructor
@EqualsAndHashCode(callSuper = false, onlyExplicitlyIncluded = true)
public class User {
   @Id
   @GeneratedValue(strategy = GenerationType.IDENTITY)
   @EqualsAndHashCode.Include
   private long id;

   @Column(name = "username")
   private String username;

   @Column(name = "password")
   private String password;

   @Column(name = "enabled")
   private boolean enabled;

   /*
    * Inserting of data from data.sql to the database does not work if we will not add the joinColumns in the @JoinTable annotation.
    */
   @ManyToMany(fetch = FetchType.EAGER)
   @JoinTable(name = "user_role_link", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "role_id"))
   @ToString.Exclude
   private Set<Role> roles;
}
