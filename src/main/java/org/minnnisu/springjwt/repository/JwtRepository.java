package org.minnnisu.springjwt.repository;

import org.minnnisu.springjwt.domain.Jwt;
import org.springframework.data.repository.CrudRepository;

public interface JwtRepository extends CrudRepository<Jwt, String> {
}