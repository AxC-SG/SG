package com.prototype.vulnwatch.service;
import static org.junit.jupiter.api.Assertions.*;
import java.util.*;
import org.junit.jupiter.api.Test;
class IsolatedCatalogVersionServiceTest {
 @Test void acceptsContinuation() {
  assertDoesNotThrow(()->IsolatedCatalogVersionService.validateBatch(10,List.of(new IsolatedCatalogVersionService.Row(11,UUID.randomUUID(),"{}"))));
 }
 @Test void rejectsSkippedOrdinal() {
  assertThrows(IllegalArgumentException.class,()->IsolatedCatalogVersionService.validateBatch(10,List.of(new IsolatedCatalogVersionService.Row(12,UUID.randomUUID(),"{}"))));
 }
 @Test void rejectsDuplicateCanonicalProjection() {
  UUID id=UUID.randomUUID();
  assertThrows(IllegalArgumentException.class,()->IsolatedCatalogVersionService.validateBatch(0,List.of(new IsolatedCatalogVersionService.Row(1,id,"{}"),new IsolatedCatalogVersionService.Row(2,id,"{}"))));
 }
}
