package com.captain.authorizationserver.repos;


import com.captain.authorizationserver.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepo extends JpaRepository<User, Long> {
	User findByEmail(String email);
}
