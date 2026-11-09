package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.ownership.DirectoryImportService;
import com.prototype.vulnwatch.service.ownership.DirectoryImportService.Kind;
import com.prototype.vulnwatch.service.ownership.DirectoryImportService.Report;
import com.prototype.vulnwatch.service.ownership.DirectoryService;
import com.prototype.vulnwatch.service.ownership.DirectoryService.DirectoryGroup;
import com.prototype.vulnwatch.service.ownership.DirectoryService.DirectoryUser;
import java.io.IOException;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

/**
 * People, groups, memberships and CSV imports (plan §8.1). Directory records never grant Scoutgrid access.
 * Reads return masked email and employee ID; unmasking is a separate restricted action that is not offered here.
 */
@RestController
@RequestMapping("/api/directory")
public class DirectoryController {

    public record UserView(UUID id, String displayName, String emailMasked, String employeeIdMasked, UUID managerUserId,
                           String status, long version) { }

    public record CreateUserRequest(String displayName, String email, String employeeId, UUID managerUserId) { }

    public record UpdateUserRequest(String displayName, String email, String employeeId, UUID managerUserId, Boolean clearManager,
                                    String status, long version) { }

    public record GroupRequest(String displayName, String status, Long version) { }

    public record MemberRequest(UUID userId) { }

    private final DirectoryService directory;
    private final DirectoryImportService imports;
    private final RequestActorService actors;

    public DirectoryController(DirectoryService directory, DirectoryImportService imports, RequestActorService actors) {
        this.directory = directory;
        this.imports = imports;
        this.actors = actors;
    }

    @GetMapping("/users")
    @PreAuthorize("@ownershipAuthorization.can('VIEW_DIRECTORY')")
    public List<UserView> searchUsers(@RequestParam("q") String query, @RequestParam(defaultValue = "25") int limit) {
        return directory.searchUsers(query, limit).stream().map(DirectoryController::view).toList();
    }

    @GetMapping("/users/{id}")
    @PreAuthorize("@ownershipAuthorization.can('VIEW_DIRECTORY')")
    public UserView user(@PathVariable UUID id) {
        return directory.user(id).map(DirectoryController::view).orElseThrow(() -> notFound("Person not found"));
    }

    @PostMapping("/users")
    @PreAuthorize("@ownershipAuthorization.can('WRITE_DIRECTORY')")
    public ResponseEntity<UserView> createUser(@RequestBody CreateUserRequest req) {
        String actor = actor();
        DirectoryUser created = directory.createUser(req.displayName(), req.email(), req.employeeId(), req.managerUserId(),
                directory.manualSource(actor), actor);
        return ResponseEntity.status(HttpStatus.CREATED).body(view(created));
    }

    @PatchMapping("/users/{id}")
    @PreAuthorize("@ownershipAuthorization.can('WRITE_DIRECTORY')")
    public UserView updateUser(@PathVariable UUID id, @RequestBody UpdateUserRequest req) {
        String actor = actor();
        DirectoryUser updated = directory.updateUser(id, req.displayName(), req.email(), req.employeeId(), req.managerUserId(),
                Boolean.TRUE.equals(req.clearManager()), req.version(), actor);
        if (req.status() != null && !req.status().equalsIgnoreCase(updated.status())) {
            updated = directory.setUserStatus(id, req.status().toUpperCase(Locale.ROOT), updated.version(), actor);
        }
        return view(updated);
    }

    @GetMapping("/groups")
    @PreAuthorize("@ownershipAuthorization.can('VIEW_DIRECTORY')")
    public List<DirectoryGroup> searchGroups(@RequestParam(value = "q", defaultValue = "") String query,
                                             @RequestParam(defaultValue = "25") int limit) {
        return directory.searchGroups(query, limit);
    }

    @PostMapping("/groups")
    @PreAuthorize("@ownershipAuthorization.can('WRITE_DIRECTORY')")
    public ResponseEntity<DirectoryGroup> createGroup(@RequestBody GroupRequest req) {
        String actor = actor();
        return ResponseEntity.status(HttpStatus.CREATED).body(directory.createGroup(req.displayName(), directory.manualSource(actor), actor));
    }

    @PatchMapping("/groups/{id}")
    @PreAuthorize("@ownershipAuthorization.can('WRITE_DIRECTORY')")
    public DirectoryGroup updateGroup(@PathVariable UUID id, @RequestBody GroupRequest req) {
        if (req.version() == null) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "version is required");
        return directory.updateGroup(id, req.displayName(), req.status() == null ? null : req.status().toUpperCase(Locale.ROOT),
                req.version(), actor());
    }

    @GetMapping("/groups/{id}/members")
    @PreAuthorize("@ownershipAuthorization.can('VIEW_DIRECTORY')")
    public List<DirectoryService.Membership> members(@PathVariable UUID id) {
        directory.group(id).orElseThrow(() -> notFound("Group not found"));
        return directory.members(id);
    }

    @PostMapping("/groups/{id}/members")
    @PreAuthorize("@ownershipAuthorization.can('WRITE_DIRECTORY')")
    public ResponseEntity<Void> addMember(@PathVariable UUID id, @RequestBody MemberRequest req) {
        String actor = actor();
        boolean changed = directory.addMember(id, req.userId(), directory.manualSource(actor), actor);
        return ResponseEntity.status(changed ? HttpStatus.CREATED : HttpStatus.OK).build();
    }

    @DeleteMapping("/groups/{id}/members/{userId}")
    @PreAuthorize("@ownershipAuthorization.can('WRITE_DIRECTORY')")
    public ResponseEntity<Void> removeMember(@PathVariable UUID id, @PathVariable UUID userId) {
        String actor = actor();
        directory.group(id).orElseThrow(() -> notFound("Group not found"));
        directory.removeMember(id, userId, directory.manualSource(actor), actor);
        return ResponseEntity.noContent().build();
    }

    @GetMapping(value = "/imports/templates/{kind}", produces = "text/csv")
    @PreAuthorize("@ownershipAuthorization.can('IMPORT_DIRECTORY')")
    public ResponseEntity<String> template(@PathVariable String kind) {
        Kind k = kind(kind);
        return ResponseEntity.ok().header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + k.name().toLowerCase(Locale.ROOT) + ".csv\"")
                .contentType(MediaType.parseMediaType("text/csv")).body(DirectoryImportService.template(k));
    }

    @PostMapping(value = "/imports/preview", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @PreAuthorize("@ownershipAuthorization.can('IMPORT_DIRECTORY')")
    public Report preview(@RequestParam("kind") String kind, @RequestParam("file") MultipartFile file) {
        return imports.preview(kind(kind), bytes(file), actor());
    }

    @PostMapping(value = "/imports/{previewToken}/commit", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @PreAuthorize("@ownershipAuthorization.can('IMPORT_DIRECTORY')")
    public Report commit(@PathVariable UUID previewToken, @RequestParam("file") MultipartFile file) {
        return imports.commit(previewToken, bytes(file), actor());
    }

    private String actor() {
        return actors.currentActor().userId();
    }

    private static Kind kind(String value) {
        try {
            return Kind.valueOf(value.toUpperCase(Locale.ROOT).replace('-', '_'));
        } catch (IllegalArgumentException | NullPointerException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown import kind");
        }
    }

    private static byte[] bytes(MultipartFile file) {
        try {
            return file.getBytes();
        } catch (IOException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "The upload could not be read");
        }
    }

    static UserView view(DirectoryUser u) {
        return new UserView(u.id(), u.displayName(), maskEmail(u.email()), maskTail(u.employeeId()), u.managerUserId(), u.status(), u.version());
    }

    static String maskEmail(String email) {
        if (email == null) return null;
        int at = email.indexOf('@');
        if (at <= 0) return "***";
        return email.charAt(0) + "***" + email.substring(at);
    }

    static String maskTail(String value) {
        if (value == null) return null;
        return value.length() <= 2 ? "**" : "***" + value.substring(value.length() - 2);
    }

    private static ResponseStatusException notFound(String message) {
        return new ResponseStatusException(HttpStatus.NOT_FOUND, message);
    }
}
