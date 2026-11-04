package com.prototype.vulnwatch.service.cbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayInputStream;
import java.util.*;
import javax.xml.parsers.DocumentBuilderFactory;
import org.springframework.stereotype.Service;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * Extracts declared relationships between cryptographic assets from a CycloneDX CBOM.
 *
 * <ul>
 *   <li>{@code DEPENDS_ON}: the CycloneDX dependency graph (JSON and XML).</li>
 *   <li>{@code USES_ALGORITHM}: key/secret {@code algorithmRef}, certificate {@code signatureAlgorithmRef},
 *       protocol {@code cryptoRefArray} and cipher-suite algorithms (usage relationships).</li>
 *   <li>{@code SECURED_BY}: key material protected by another algorithm ({@code securedBy.algorithmRef}, custody).</li>
 *   <li>{@code CERTIFIES_KEY}: a certificate's {@code subjectPublicKeyRef} (certificate-to-key).</li>
 * </ul>
 * Application ownership edges are added by ingestion, which knows the owning asset. Typed crypto
 * references are read from JSON documents; XML documents contribute dependency edges only.
 */
@Service
public class CbomRelationshipExtractor {
    public static final String DEPENDS_ON = "DEPENDS_ON";
    public static final String USES_ALGORITHM = "USES_ALGORITHM";
    public static final String SECURED_BY = "SECURED_BY";
    public static final String CERTIFIES_KEY = "CERTIFIES_KEY";
    public static final String APPLICATION_USES = "APPLICATION_USES";

    private final ObjectMapper mapper;
    public CbomRelationshipExtractor(ObjectMapper mapper){this.mapper=mapper;}

    public List<DeclaredRelationship> extract(byte[] content){
        try{return first(content)=='<'?xml(content):json(content);}catch(Exception ignored){return List.of();}
    }

    private List<DeclaredRelationship> json(byte[] content)throws Exception{
        JsonNode root=mapper.readTree(content);if(root.path("cbom").isObject())root=root.path("cbom");
        Set<DeclaredRelationship> result=new LinkedHashSet<>();
        for(JsonNode dependency:root.path("dependencies")){String source=text(dependency,"ref");
            for(JsonNode target:dependency.path("dependsOn"))if(source!=null&&target.isTextual())
                result.add(new DeclaredRelationship(source,target.asText(),DEPENDS_ON,"Declared by CycloneDX dependency graph"));}
        for(JsonNode component:root.path("components")){
            String ref=text(component,"bom-ref");if(ref==null)continue;
            JsonNode crypto=component.path("cryptoProperties");
            JsonNode material=crypto.path("relatedCryptoMaterialProperties");
            add(result,ref,text(material,"algorithmRef"),USES_ALGORITHM,"Key material declares its algorithm (algorithmRef)");
            add(result,ref,text(material.path("securedBy"),"algorithmRef"),SECURED_BY,
                    "Key material is secured by this algorithm" + mechanism(material.path("securedBy")));
            JsonNode certificate=crypto.path("certificateProperties");
            add(result,ref,text(certificate,"signatureAlgorithmRef"),USES_ALGORITHM,"Certificate signature algorithm (signatureAlgorithmRef)");
            add(result,ref,text(certificate,"subjectPublicKeyRef"),CERTIFIES_KEY,"Certificate binds this public key (subjectPublicKeyRef)");
            JsonNode protocol=crypto.path("protocolProperties");
            for(JsonNode target:protocol.path("cryptoRefArray"))if(target.isTextual())
                add(result,ref,target.asText(),USES_ALGORITHM,"Protocol references this algorithm (cryptoRefArray)");
            for(JsonNode suite:protocol.path("cipherSuites"))for(JsonNode target:suite.path("algorithms"))if(target.isTextual())
                add(result,ref,target.asText(),USES_ALGORITHM,"Cipher suite "+Objects.requireNonNullElse(text(suite,"name"),"")+" uses this algorithm");
        }
        return List.copyOf(result);
    }

    private List<DeclaredRelationship> xml(byte[] content)throws Exception{
        DocumentBuilderFactory f=DocumentBuilderFactory.newInstance();f.setNamespaceAware(true);f.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);
        var doc=f.newDocumentBuilder().parse(new ByteArrayInputStream(content));List<DeclaredRelationship> result=new ArrayList<>();
        var values=doc.getElementsByTagNameNS("*","dependency");
        for(int i=0;i<values.getLength();i++){Element source=(Element)values.item(i);if(source.getParentNode() instanceof Element parent&&"dependency".equals(parent.getLocalName()))continue;
            String sourceRef=source.getAttribute("ref");for(Node child=source.getFirstChild();child!=null;child=child.getNextSibling())if(child instanceof Element target&&"dependency".equals(target.getLocalName())){
                String targetRef=target.getAttribute("ref");if(!sourceRef.isBlank()&&!targetRef.isBlank())result.add(new DeclaredRelationship(sourceRef,targetRef,DEPENDS_ON,"Declared by CycloneDX dependency graph"));}}
        return result;
    }

    private static void add(Set<DeclaredRelationship> out,String source,String target,String type,String summary){
        if(target!=null&&!target.equals(source))out.add(new DeclaredRelationship(source,target,type,summary));
    }
    private static String mechanism(JsonNode securedBy){String value=securedBy.path("mechanism").asText(null);return value==null||value.isBlank()?"":" ("+value+")";}
    private char first(byte[] content){for(byte b:content){char c=(char)b;if(!Character.isWhitespace(c))return c;}return 0;}
    private static String text(JsonNode node,String field){String v=node.path(field).asText(null);return v==null||v.isBlank()?null:v;}

    public record DeclaredRelationship(String sourceRef,String targetRef,String relationshipType,String evidenceSummary){
        /** Dependency-graph edge, kept for callers that only know the CycloneDX dependency pair. */
        public DeclaredRelationship(String sourceRef,String targetRef){this(sourceRef,targetRef,DEPENDS_ON,"Declared by CycloneDX dependency graph");}
    }
}
