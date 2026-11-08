-- migration-guard: platform-only
CREATE TABLE platform.standard_enrollment_policy (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    customer_limit integer NOT NULL CHECK (customer_limit IN (3, 10))
);

-- Bootstrap grants platform table DML to the runtime role. Keep the policy
-- owner-only and expose just its presence to the lifecycle trigger.
ALTER TABLE platform.standard_enrollment_policy ENABLE ROW LEVEL SECURITY;

CREATE FUNCTION platform.standard_enrollment_enabled() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog
AS $$ SELECT EXISTS (SELECT 1 FROM platform.standard_enrollment_policy) $$;

CREATE FUNCTION platform.guard_standard_tenant_lifecycle() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF current_user = pg_get_userbyid((SELECT relowner FROM pg_class WHERE oid = TG_RELID))
        OR NOT platform.standard_enrollment_enabled() THEN
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END IF;

    IF TG_OP = 'UPDATE' THEN
        IF ROW(NEW.id, NEW.classification, NEW.schema_name, NEW.slug, NEW.deleted_at,
               NEW.demo_expires_at, NEW.expired_at, NEW.purge_started_at, NEW.purged_at)
            IS NOT DISTINCT FROM
           ROW(OLD.id, OLD.classification, OLD.schema_name, OLD.slug, OLD.deleted_at,
               OLD.demo_expires_at, OLD.expired_at, OLD.purge_started_at, OLD.purged_at)
           AND (NEW.status = OLD.status OR
               (NEW.status IN ('ACTIVE', 'SUSPENDED') AND OLD.status IN ('ACTIVE', 'SUSPENDED'))) THEN
            RETURN NEW;
        END IF;
    END IF;

    RAISE EXCEPTION 'Standard tenant lifecycle changes require the exit-once provisioning task'
        USING ERRCODE = '42501';
END;
$$;

CREATE TRIGGER guard_standard_tenant_insert BEFORE INSERT ON platform.tenants
    FOR EACH ROW EXECUTE FUNCTION platform.guard_standard_tenant_lifecycle();
CREATE TRIGGER guard_standard_tenant_update BEFORE UPDATE OR DELETE ON platform.tenants
    FOR EACH ROW EXECUTE FUNCTION platform.guard_standard_tenant_lifecycle();
