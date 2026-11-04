package com.prototype.vulnwatch.dto;
import java.util.List;
import java.util.UUID;
public record CbomDiffResponse(UUID fromBomId,UUID toBomId,int addedCount,int removedCount,int changedCount,List<Change> changes){
    public record Change(String changeType,String identity,UUID fromComponentId,UUID toComponentId,String name,List<String> changedFields){}
}
