package com.vc.volunteeringcommunity.auth.repository;

import com.vc.volunteeringcommunity.auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);

    Boolean existsByRole(String role);

    Optional<User> findByRole(String role);

}
