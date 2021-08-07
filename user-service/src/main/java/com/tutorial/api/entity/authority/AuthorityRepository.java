package com.tutorial.api.entity.authority;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AuthorityRepository extends JpaRepository<Authority, Long> {
   Authority findByRoleId(long id);
}
