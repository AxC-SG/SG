package com.prototype.vulnwatch.service.cbom;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import org.springframework.stereotype.Service;

@Service
public class CbomAssessmentReportService {
    private final CbomAssessmentService assessments; private final ObjectMapper mapper;
    public CbomAssessmentReportService(CbomAssessmentService assessments,ObjectMapper mapper){this.assessments=assessments;this.mapper=mapper;}
    public Report generate(Tenant tenant,UUID runId,String format){
        var run=assessments.get(tenant,runId);Map<String,Object> body=new LinkedHashMap<>();
        body.put("schemaVersion","1.0");body.put("signatureStatus","UNSIGNED");body.put("limitation","Checksum verifies content consistency, not authenticity");
        body.put("assessment",run);String canonical=write(body);String checksum=sha256(canonical);body.put("checksumSha256",checksum);
        if("html".equalsIgnoreCase(format)){String html="<!doctype html><html><head><meta charset=\"utf-8\"><title>CBOM Assessment</title></head><body>"
                +"<h1>Cryptographic Security Assessment</h1><p><strong>Unsigned report</strong> — checksum verifies content consistency, not authenticity.</p>"
                +"<dl><dt>Assessment</dt><dd>"+escape(run.id().toString())+"</dd><dt>Artifact checksum</dt><dd>"+escape(run.artifactChecksum())+"</dd>"
                +"<dt>Rule package</dt><dd>"+escape(run.rulePackageId()+"@"+run.rulePackageVersion())+"</dd><dt>Evaluator</dt><dd>"+escape(run.evaluatorVersion())+"</dd>"
                +"<dt>Status</dt><dd>"+escape(run.status())+"</dd><dt>Validation</dt><dd>"+escape(run.validationOutcome())+"</dd><dt>Report checksum</dt><dd>"+checksum+"</dd></dl>"
                +"<h2>Validation issues</h2><ul>"+run.validationIssues().stream().map(v->"<li>"+escape(v.code()+": "+v.message())+"</li>").reduce("",String::concat)+"</ul></body></html>";
            return new Report("text/html;charset=UTF-8","cbom-assessment-"+run.id()+".html",html.getBytes(StandardCharsets.UTF_8),checksum);
        }
        return new Report("application/json","cbom-assessment-"+run.id()+".json",write(body).getBytes(StandardCharsets.UTF_8),checksum);
    }
    private String write(Object value){try{return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(value);}catch(Exception e){throw new IllegalStateException("Report generation failed",e);}}
    private String sha256(String value){try{return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));}catch(Exception e){throw new IllegalStateException(e);}}
    private String escape(String v){return v==null?"":v.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;").replace("'","&#39;");}
    public record Report(String contentType,String filename,byte[] content,String checksum){}
}
