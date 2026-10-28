package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.FixRecordCve;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface FixRecordCveRepository extends JpaRepository<FixRecordCve, UUID> {
    List<FixRecordCve> findByFixId(UUID fixId);
    List<FixRecordCve> findByFixIdIn(Collection<UUID> fixIds);
    List<FixRecordCve> findByCveId(String cveId);
    Optional<FixRecordCve> findByFixIdAndCveId(UUID fixId, String cveId);
    void deleteByFixIdAndSource(UUID fixId, String source);
}
