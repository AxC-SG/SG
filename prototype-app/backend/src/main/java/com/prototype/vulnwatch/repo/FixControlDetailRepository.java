package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.FixControlDetail;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface FixControlDetailRepository extends JpaRepository<FixControlDetail, UUID> {
}
