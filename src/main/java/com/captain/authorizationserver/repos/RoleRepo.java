package com.captain.authorizationserver.repos;


import com.captain.authorizationserver.entities.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepo extends JpaRepository<Role, Long> {

}
