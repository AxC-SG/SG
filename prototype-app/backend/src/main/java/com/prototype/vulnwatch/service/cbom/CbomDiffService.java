package com.prototype.vulnwatch.service.cbom;
import com.prototype.vulnwatch.domain.*;
import com.prototype.vulnwatch.dto.CbomDiffResponse;
import com.prototype.vulnwatch.repo.*;
import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CbomDiffService {
    private final BomIngestionRecordRepository boms; private final CbomComponentRepository components;
    public CbomDiffService(BomIngestionRecordRepository boms,CbomComponentRepository components){this.boms=boms;this.components=components;}
    @Transactional(readOnly=true)
    public CbomDiffResponse diff(Tenant tenant,UUID fromId,UUID toId){
        requireCbom(tenant,fromId);requireCbom(tenant,toId);
        Map<String,CbomComponent> from=index(components.findByTenant_IdAndSourceBom_IdOrderByNameAsc(tenant.getId(),fromId));
        Map<String,CbomComponent> to=index(components.findByTenant_IdAndSourceBom_IdOrderByNameAsc(tenant.getId(),toId));
        List<CbomDiffResponse.Change> changes=new ArrayList<>();
        for(var entry:from.entrySet()){
            CbomComponent next=to.get(entry.getKey());
            if(next==null)changes.add(change("REMOVED",entry.getKey(),entry.getValue(),null,List.of()));
            else {List<String> fields=changed(entry.getValue(),next);if(!fields.isEmpty())changes.add(change("CHANGED",entry.getKey(),entry.getValue(),next,fields));}
        }
        for(var entry:to.entrySet())if(!from.containsKey(entry.getKey()))changes.add(change("ADDED",entry.getKey(),null,entry.getValue(),List.of()));
        changes.sort(Comparator.comparing(CbomDiffResponse.Change::changeType).thenComparing(CbomDiffResponse.Change::identity));
        return new CbomDiffResponse(fromId,toId,(int)changes.stream().filter(v->v.changeType().equals("ADDED")).count(),
                (int)changes.stream().filter(v->v.changeType().equals("REMOVED")).count(),(int)changes.stream().filter(v->v.changeType().equals("CHANGED")).count(),changes);
    }
    private void requireCbom(Tenant tenant,UUID id){boms.findById(id).filter(v->v.getTenant().getId().equals(tenant.getId())&&v.getBomType()==BomType.CBOM).orElseThrow(()->new IllegalArgumentException("CBOM artifact not found"));}
    private Map<String,CbomComponent> index(List<CbomComponent> values){Map<String,CbomComponent> result=new LinkedHashMap<>();for(CbomComponent v:values)result.putIfAbsent(identity(v),v);return result;}
    private String identity(CbomComponent v){if(v.getBomRef()!=null&&!v.getBomRef().isBlank())return "bom-ref:"+v.getBomRef();return "fingerprint:"+v.getComponentFingerprint();}
    private List<String> changed(CbomComponent a,CbomComponent b){List<String> f=new ArrayList<>();field(f,"primitive",a.getPrimitive(),b.getPrimitive());field(f,"keySize",a.getKeySize(),b.getKeySize());field(f,"curve",a.getCurve(),b.getCurve());field(f,"protocolVersion",a.getProtocolVersion(),b.getProtocolVersion());field(f,"state",a.getState(),b.getState());field(f,"storageLocation",a.getStorageLocation(),b.getStorageLocation());field(f,"notAfter",a.getNotAfter(),b.getNotAfter());return f;}
    private void field(List<String> f,String name,Object a,Object b){if(!Objects.equals(a,b))f.add(name);}
    private CbomDiffResponse.Change change(String type,String identity,CbomComponent a,CbomComponent b,List<String> fields){CbomComponent value=b==null?a:b;return new CbomDiffResponse.Change(type,identity,a==null?null:a.getId(),b==null?null:b.getId(),value.getName(),fields);}
}
