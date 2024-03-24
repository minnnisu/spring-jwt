package org.minnnisu.springjwt.repository;

import org.minnnisu.springjwt.domain.Users;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<Users, Long> {

    Optional<Users> findByUsername(String name);
}