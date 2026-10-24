-- migration-guard: platform-only
ALTER TABLE platform.tenants ADD COLUMN classification varchar(16) NOT NULL DEFAULT 'CUSTOMER';
UPDATE platform.tenants SET classification='INTERNAL', name='SG Internal', plan_code='ENTERPRISE',
    demo_expires_at=null, demo_source=null, expired_at=null,
    max_connector_count=1000, max_service_account_count=1000, max_daily_sbom_uploads=10000,
    max_export_rows=1000000, max_daily_exposure_refreshes=10000
 WHERE schema_name='tenant_default';
ALTER TABLE platform.tenants ADD CONSTRAINT tenant_classification_check
 CHECK (classification IN ('INTERNAL','CUSTOMER') AND
        ((classification='INTERNAL') = (schema_name='tenant_default')));
CREATE UNIQUE INDEX one_internal_tenant ON platform.tenants(classification) WHERE classification='INTERNAL';

CREATE FUNCTION platform.protect_internal_tenant() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN
   IF OLD.classification='INTERNAL' THEN RAISE EXCEPTION 'SG Internal cannot be deleted'; END IF;
   RETURN OLD;
 END IF;
 IF TG_OP='UPDATE' AND OLD.classification='INTERNAL' AND
    (NEW.id<>OLD.id OR NEW.schema_name<>OLD.schema_name OR NEW.classification<>OLD.classification OR NEW.slug IS DISTINCT FROM OLD.slug)
 THEN RAISE EXCEPTION 'Reserved internal identity cannot be changed'; END IF;
 IF NEW.classification='INTERNAL' AND
    (NEW.name<>'SG Internal' OR NEW.plan_code<>'ENTERPRISE' OR NEW.demo_expires_at IS NOT NULL OR
     NEW.demo_source IS NOT NULL OR NEW.expired_at IS NOT NULL OR NEW.deleted_at IS NOT NULL OR
     NEW.purge_started_at IS NOT NULL OR NEW.purged_at IS NOT NULL OR NEW.status IN ('EXPIRED','DELETED','PURGING','PURGED'))
 THEN RAISE EXCEPTION 'SG Internal is protected from demo expiry and deletion'; END IF;
 IF NEW.classification='CUSTOMER' AND
    (lower(NEW.name)='sg internal' OR lower(NEW.slug) IN ('default-workspace','sg-internal'))
 THEN RAISE EXCEPTION 'Reserved internal tenant identity'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER protect_internal_tenant_insert BEFORE INSERT ON platform.tenants FOR EACH ROW EXECUTE FUNCTION platform.protect_internal_tenant();
CREATE TRIGGER protect_internal_tenant_update BEFORE UPDATE ON platform.tenants FOR EACH ROW EXECUTE FUNCTION platform.protect_internal_tenant();
CREATE TRIGGER protect_internal_tenant_delete BEFORE DELETE ON platform.tenants FOR EACH ROW EXECUTE FUNCTION platform.protect_internal_tenant();

-- Revoke the historical automatic owner-to-playground bridge. Explicit support
-- grants and manually administered memberships retain their existing audit trail.
UPDATE platform.tenant_memberships SET status='SUSPENDED', updated_at=now()
 WHERE provenance='PLAYGROUND_BOOTSTRAP' AND status='ACTIVE';

ALTER TABLE platform.invitation_email_outbox ALTER COLUMN tenant_id DROP NOT NULL;
ALTER TABLE platform.invitation_email_outbox ADD CONSTRAINT invitation_delivery_scope_check CHECK (
 (delivery_type='PLATFORM_OWNER_SETUP' AND tenant_id IS NULL) OR
 (delivery_type IN ('TENANT_INVITE','DEMO_INVITE','INTERNAL_ADMIN_SETUP') AND tenant_id IS NOT NULL));

INSERT INTO platform.tenant_entitlement_overrides(id,tenant_id,entitlement_key,enabled,reason,created_at,updated_at)
 SELECT md5(t.id::text||d.key)::uuid,t.id,d.key,true,'SG Internal installation entitlement',now(),now()
 FROM platform.tenants t CROSS JOIN platform.entitlement_definitions d WHERE t.classification='INTERNAL'
 ON CONFLICT(tenant_id,entitlement_key) DO NOTHING;
