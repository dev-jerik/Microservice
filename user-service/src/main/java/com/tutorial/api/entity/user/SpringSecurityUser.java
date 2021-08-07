package com.tutorial.api.entity.user;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class SpringSecurityUser implements UserDetails {

   /**
    * 
    */
   private static final long serialVersionUID = 1L;
   private final User user;
   private final Collection<GrantedAuthority> authorities;

   public SpringSecurityUser(User user, Collection<GrantedAuthority> authorities) {
      this.user = user;
      this.authorities = authorities;
   }

   @Override
   public Collection<? extends GrantedAuthority> getAuthorities() {
      return authorities;
   }

   @Override
   public String getPassword() {
      return user.getPassword();
   }

   @Override
   public String getUsername() {
      return user.getUsername();
   }

   @Override
   public boolean isAccountNonExpired() {
      return user.isEnabled();
   }

   @Override
   public boolean isAccountNonLocked() {
      return user.isEnabled();
   }

   @Override
   public boolean isCredentialsNonExpired() {
      return user.isEnabled();
   }

   @Override
   public boolean isEnabled() {
      return user.isEnabled();
   }

}
