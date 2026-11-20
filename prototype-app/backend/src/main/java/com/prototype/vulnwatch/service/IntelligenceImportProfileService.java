package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.service.vulningestion.VulnerabilitySyncRunService;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

@Service
public class IntelligenceImportProfileService {
    public record Profile(UUID id, String name, Set<String> sources, Integer publicationYearFrom,
            Integer publicationYearTo, Double minCvss, Double maxCvss, Set<String> severities,
            boolean includeUnknownScores) {}
    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final VulnerabilitySyncRunService runs;
    public IntelligenceImportProfileService(JdbcTemplate jdbc, ObjectMapper mapper, VulnerabilitySyncRunService runs) {
        this.jdbc=jdbc; this.mapper=mapper; this.runs=runs;
    }
    public List<Profile> list() {
        return jdbc.query("select profile::text from platform.intelligence_import_profiles order by created_at,id",
                (rs,n)->decode(rs.getString(1)));
    }
    private Profile decode(String json) {
        try { return mapper.readValue(json,Profile.class); }
        catch (java.io.IOException ex) { throw new IllegalStateException("Invalid stored import profile",ex); }
    }
    public static void validate(Profile p) {
        if (p==null || p.name()==null || p.name().isBlank() || p.name().length()>200) bad("Profile name is required (maximum 200 characters)");
        if (p.sources()==null || p.sources().isEmpty() || !Set.of("NVD").containsAll(p.sources()))
            bad("Import profiles currently support NVD only; other sources cannot execute scoped imports yet");
        if (p.publicationYearFrom()!=null && (p.publicationYearFrom()<1 || p.publicationYearFrom()>9999)
                || p.publicationYearTo()!=null && (p.publicationYearTo()<1 || p.publicationYearTo()>9999)
                || p.publicationYearFrom()!=null && p.publicationYearTo()!=null && p.publicationYearFrom()>p.publicationYearTo()) bad("Invalid publication year range");
        if (p.minCvss()!=null && (!Double.isFinite(p.minCvss()) || p.minCvss()<0 || p.minCvss()>10)
                || p.maxCvss()!=null && (!Double.isFinite(p.maxCvss()) || p.maxCvss()<0 || p.maxCvss()>10)
                || p.minCvss()!=null && p.maxCvss()!=null && p.minCvss()>p.maxCvss()) bad("CVSS range must be within 0..10 and ordered");
        if (p.severities()!=null && !Set.of("CRITICAL","HIGH","MEDIUM","LOW","NONE","UNKNOWN").containsAll(p.severities())) bad("Unsupported severity");
    }
    private static void bad(String message) { throw new ResponseStatusException(HttpStatus.BAD_REQUEST,message); }
    @Transactional
    public Profile save(Profile input) {
        validate(input);
        // Every save creates an immutable revision, including edits submitted with an existing ID.
        Profile p=new Profile(UUID.randomUUID(),input.name().trim(),Set.copyOf(input.sources()),input.publicationYearFrom(),input.publicationYearTo(),input.minCvss(),input.maxCvss(),input.severities()==null?Set.of():Set.copyOf(input.severities()),input.includeUnknownScores());
        try { jdbc.update("insert into platform.intelligence_import_profiles(id,name,profile) values(?,?,?::jsonb)",p.id(),p.name(),mapper.writeValueAsString(p)); }
        catch (java.io.IOException ex) { throw new IllegalStateException(ex); }
        return p;
    }
    @Transactional
    public Object run(UUID id) {
        Profile p=jdbc.query("select profile::text from platform.intelligence_import_profiles where id=?",(rs,n)->decode(rs.getString(1)),id).stream().findFirst()
                .orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND,"Import profile not found"));
        validate(p);
        var decision=runs.prepareQueuedRun("NVD_FULL",List.of("NVD","NVD_FULL"),Map.of("triggerMode","full","importProfile",p,"importScopeKey","profile:"+p.id(),"publicationMode","MANUAL"));
        if(!decision.queuedNewRun()) throw new ResponseStatusException(HttpStatus.CONFLICT,"NVD integration already active; profile was not queued");
        return decision.toResponse("NVD ingestion is already active; profile was not queued", "NVD profile import queued");
    }
    public Object schedule(UUID id) {
        var profiles=jdbc.queryForList("select id from platform.intelligence_import_profiles where id=?",UUID.class,id);
        if(profiles.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Import profile not found");
        var rows=jdbc.queryForList("select enabled,interval_hours from platform.intelligence_feed_schedules where sync_type='NVD' and import_profile_id=?",id);
        if(rows.isEmpty()) return Map.of("id",id,"enabled",false,"intervalHours",24);
        return Map.of("id",id,"enabled",rows.get(0).get("enabled"),"intervalHours",rows.get(0).get("interval_hours"));
    }
    @Transactional
    public Object schedule(UUID id,boolean enabled,int intervalHours) {
        if(intervalHours<1 || intervalHours>8760) bad("Interval must be 1..8760 hours");
        var profiles=jdbc.query("select profile::text from platform.intelligence_import_profiles where id=?",(rs,n)->decode(rs.getString(1)),id);
        if(profiles.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Import profile not found");
        validate(profiles.get(0));
        int changed=jdbc.update("update platform.intelligence_feed_schedules set import_profile_id=?,enabled=?,interval_hours=?,next_due_at=clock_timestamp()+make_interval(hours=>?) where sync_type='NVD'",id,enabled,intervalHours,intervalHours);
        if(changed!=1) throw new ResponseStatusException(HttpStatus.CONFLICT,"NVD schedule has not been initialized");
        return Map.of("id",id,"enabled",enabled,"intervalHours",intervalHours);
    }
}
