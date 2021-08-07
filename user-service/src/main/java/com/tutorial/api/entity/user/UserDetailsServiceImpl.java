package com.tutorial.api.entity.user;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.tutorial.api.entity.authority.Authority;
import com.tutorial.api.entity.authority.AuthorityRepository;
import com.tutorial.api.entity.role.Role;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
   private final UserService userService;
   private final AuthorityRepository authorityRepository;

   public UserDetailsServiceImpl(UserService userService, AuthorityRepository authorityRepository) {
      this.userService = userService;
      this.authorityRepository = authorityRepository;
   }

   @Override
   public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
      User user = userService.findUserByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException("User with username, " + username + ", does not exist."));

      Collection<GrantedAuthority> authorities = new HashSet<GrantedAuthority>();
      Set<Role> roles = user.getRoles();

      for (Role role : roles) {
         authorities.add(role);
         Authority authority = authorityRepository.findByRoleId(role.getId());

         if (authority != null) {
            authorities.add(authority);
         }
      }
      return new SpringSecurityUser(user, authorities);
   }

}
