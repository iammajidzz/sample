package com.majid.sample;

import org.opensaml.*;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.xml.encryption.ChainingEncryptedKeyResolver;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.encryption.SimpleRetrievalMethodEncryptedKeyResolver;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

@RestController
public class DecryptSAML {
    String privateKey = "-----BEGIN PRIVATE KEY-----MIIEwQIBADANBgkqhkiG9w0BAQEFAASCBKswggSnAgEAAoIBAgDO5FpMvAbGAK/iGdMF7b4Mvl6q0x1Ub1lWkSzr1uhvBB6aFcPhgcIMVSJF4MaTeLZWOlP4ei99z89zxYHAxZYzbYrkuAfzLLyJBwCH7Jt2YG1TTGjUGtRZPFcefYP9VXjnbZADQPvavUZODAbe73WO5n/HFY0+LuOAx+urVLH7JmBM+r+zdgWW2nNruSw/QqymNJzNSzH4c7BFJ6mykfFVCfEI64vKjYnr1a0sYIDSTRAByVEF6jypx62GF/36H6eo0/LfPRNcqg1a39xIEf56INwMeKRIpNw0QuNpFXfzoLO1KI53YTZkJBcZMk328TMz7oRqbdTHfng34xyvH8BZzwIDAQABAoIBAQVffNDdWTevMOIoVYij4fmmwAKjtPFKawGKh6YgUK0BaGIMCqhCnG2BkIBMFBwkWGfo3+FmGvGjgfm5uWLuPrZbM+44sUwpb0QHwIXHKUpruqsdIuPPRpCCtqh+Df14SMmJ2OGcwG2v2LGSMmN7yIvLhKoA70gcI6BmkMJEUtL47WvKdA4wgI1EROSurtTPYhwvI65m8Jx5a8byr6vZabLWz2RoFsrrxP1X5ExuijrjY3C2dPHZOS+1Q52RzyquWyDHLLSgnG17yGk/Fq0jklo/+O3Ew3osPnIfch8Xc/8Vcx1tyzgMnZ1km7fTOHO8EdnRvr0fH5+dOY0CCwm6MBTxAoGBDyv5d9pPE0Yf3MNeNaZmrdYHSRagzVg/OXi/64NFGn4JmJOhZho+Sdm7PxikWPhDxSfsI1x3Hpgq3QRjBoOGIUgoFB0v8M0kNAYUBve3bCvxlk++7De5gyO9wctYrnXEKs2yDVRf1cDQkBGY+u8WjdtBoANxEqbIDX3wsEce97Z1AoGBDaL6r4kMqdoUz6u6Za1IdDL1sfChhEzfSx+p1Kp5bdCbiQInEki992e0gUfztVMGPBhzVyEm2otgwHALfih1J3Ks2ax+r+7aGFliQZNmYUxUsqyG/lFWWQJlzxwlnEmaBeoIm1T3gDkaND0BEQHCV3M1YbcG38xayqdbZ1Op3+6zAoGBCsQ+KRu3egoNmnDabmBEBaEZUnjIbHDvjS1vpQZnB8HhtXEu3HJLOcVV6BTorGqiTUtjfESmFAQQhwAR9hFoIj4+kueTmeM6ieC2Xat1c0JME0tMRf3VnIbEpr5TlJrmNyn57ROvXtWSLGsQkSMScmDiVVeb6oyI82ooYDBYfZnxAoGBBfOay5/Z+gunR5fgq128oJJZL0chhzdxwTzZh2q7wpToPRzGZrF+z4rgeggoMnxA3Vuig2WBqqJoILUGHxKTRxtCm2IwjKKHZ1cjjhFB/rcsxCqOZFKliAWG36SeOZ7Z7TjedsTXnIvPhvsVCxIkerxakQIrquNqwMXYG7mlC4oHAoGBCWLLYjpdxIPwDIiRFDQ7k0pbQS39tX3heTjCIv+xlJD37NVepPlXVjTOcwucgRi0i7RbFDRqnZCOFOw5aWjmpR9csv8nVKvsQGGG1nI3rEUgUSQY52DZ9RPtCxX9X7Qa8gh4O6BqAbawAl+PO1JyR7ST6tokiE+6QhjyOj2Kdi/S-----END PRIVATE KEY-----";
    String encryptedSAML = "PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iIElEPSJfOGU4ZGM1ZjY5YTk4Y2M0YzFmZjM0MjdlNWNlMzQ2MDZmZDY3MmY5MWU2IiBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAxNC0wNy0xN1QwMTowMTo0OFoiIERlc3RpbmF0aW9uPSJodHRwOi8vc3AuZXhhbXBsZS5jb20vZGVtbzEvaW5kZXgucGhwP2FjcyIgSW5SZXNwb25zZVRvPSJPTkVMT0dJTl80ZmVlM2IwNDYzOTVjNGU3NTEwMTFlOTdmODkwMGI1MjczZDU2Njg1Ij4NCiAgPHNhbWw6SXNzdWVyPmh0dHA6Ly9pZHAuZXhhbXBsZS5jb20vbWV0YWRhdGEucGhwPC9zYW1sOklzc3Vlcj4NCiAgPHNhbWxwOlN0YXR1cz4NCiAgICA8c2FtbHA6U3RhdHVzQ29kZSBWYWx1ZT0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnN0YXR1czpTdWNjZXNzIi8+DQogIDwvc2FtbHA6U3RhdHVzPg0KICA8c2FtbDpBc3NlcnRpb24geG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiBJRD0icGZ4ODlkNTY1NWItM2E2Ni1lMGZlLWExNDMtZDZkYmU2MGZkOWM2IiBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAxNC0wNy0xN1QwMTowMTo0OFoiPg0KICAgIDxzYW1sOklzc3Vlcj5odHRwOi8vaWRwLmV4YW1wbGUuY29tL21ldGFkYXRhLnBocDwvc2FtbDpJc3N1ZXI+PGRzOlNpZ25hdHVyZSB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+DQogIDxkczpTaWduZWRJbmZvPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+DQogICAgPGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNyc2Etc2hhMSIvPg0KICA8ZHM6UmVmZXJlbmNlIFVSST0iI3BmeDg5ZDU2NTViLTNhNjYtZTBmZS1hMTQzLWQ2ZGJlNjBmZDljNiI+PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvZHM6VHJhbnNmb3Jtcz48ZHM6RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3NoYTEiLz48ZHM6RGlnZXN0VmFsdWU+dEVWcTNLUlRNQXRha0ppTmlkN1hhRndMdDJFPTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+PC9kczpTaWduZWRJbmZvPjxkczpTaWduYXR1cmVWYWx1ZT5Dc3pxWXFSbkFYeUh0bnhtaW1tdWNWU1lMaytaWlBhU3k1N01DZlZUSXB5Lzk4a3J5RjUrSWI0MXliN0FFaWtNTU1uUm5UWTV4Z1haQ1loTXA1dWNzOWZrM3dTaGp6a2dTTEs2WGxuMDNxYk9pKzNTNTJpbDRiYzJBR1FnLzYrRnVFbDZtUEppNDRDbTI1MXpjQW1FT3NMS25aNHdrc3ErMGphZHFNdTBpMjA9PC9kczpTaWduYXR1cmVWYWx1ZT4NCjxkczpLZXlJbmZvPjxkczpYNTA5RGF0YT48ZHM6WDUwOUNlcnRpZmljYXRlPk1JSUNhakNDQWRPZ0F3SUJBZ0lCQURBTkJna3Foa2lHOXcwQkFRMEZBREJTTVFzd0NRWURWUVFHRXdKMWN6RVRNQkVHQTFVRUNBd0tRMkZzYVdadmNtNXBZVEVWTUJNR0ExVUVDZ3dNVDI1bGJHOW5hVzRnU1c1ak1SY3dGUVlEVlFRRERBNXpjQzVsZUdGdGNHeGxMbU52YlRBZUZ3MHhOREEzTVRjeE5ERXlOVFphRncweE5UQTNNVGN4TkRFeU5UWmFNRkl4Q3pBSkJnTlZCQVlUQW5Wek1STXdFUVlEVlFRSURBcERZV3hwWm05eWJtbGhNUlV3RXdZRFZRUUtEQXhQYm1Wc2IyZHBiaUJKYm1NeEZ6QVZCZ05WQkFNTURuTndMbVY0WVcxd2JHVXVZMjl0TUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FEWngrT040SVVvSVd4Z3VrVGIxdE9pWDNiTVl6WVFpd1dQVU5NcCtGcTgyeG9Ob2dzbzJieWtaRzB5aUptNW84enYvc2Q2cEdvdWF5TWdreC8yRlNPZGMzNlQwakdiQ0h1UlNidGlhMFBFek5JUnRtVmlNcnQzQWVvV0JpZFJYbVpzeENOTHdnSVY2ZG4yV3B1RTVBejBiSGdwWm5ReFRLRmVrMEJNS1UvZDh3SURBUUFCbzFBd1RqQWRCZ05WSFE0RUZnUVVHSHhZcVpZeVg3Y1R4S1ZPRFZnWndTVGRDbnd3SHdZRFZSMGpCQmd3Rm9BVUdIeFlxWll5WDdjVHhLVk9EVmdad1NUZENud3dEQVlEVlIwVEJBVXdBd0VCL3pBTkJna3Foa2lHOXcwQkFRMEZBQU9CZ1FCeUZPbCtoTUZJQ2JkM0RKZm5wMlJnZC9kcXR0c1pHL3R5aElMV3ZFcmJpby9ERWU5OG1YcG93aFRrQzA0RU5wck95WGk3WmJVcWlpY0Y4OXVBR3l0MW9xZ1RVQ0QxVnNMYWhxSWNtcnpndW1OeVR3TEdXbzE3V0RBYTEvdXNEaGV0V0FNaGd6Ri9DbmY1ZWswbkswMG0wWVpHeWM0THpnRDBDUk9NQVNUV05nPT08L2RzOlg1MDlDZXJ0aWZpY2F0ZT48L2RzOlg1MDlEYXRhPjwvZHM6S2V5SW5mbz48L2RzOlNpZ25hdHVyZT4NCiAgICA8c2FtbDpTdWJqZWN0Pg0KICAgICAgPHNhbWw6TmFtZUlEIFNQTmFtZVF1YWxpZmllcj0iaHR0cDovL3NwLmV4YW1wbGUuY29tL2RlbW8xL21ldGFkYXRhLnBocCIgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6bmFtZWlkLWZvcm1hdDp0cmFuc2llbnQiPl9jZTNkMjk0OGI0Y2YyMDE0NmRlZTBhMGIzZGQ2ZjY5YjZjZjg2ZjYyZDc8L3NhbWw6TmFtZUlEPg0KICAgICAgPHNhbWw6U3ViamVjdENvbmZpcm1hdGlvbiBNZXRob2Q9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpjbTpiZWFyZXIiPg0KICAgICAgICA8c2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uRGF0YSBOb3RPbk9yQWZ0ZXI9IjIwMjQtMDEtMThUMDY6MjE6NDhaIiBSZWNpcGllbnQ9Imh0dHA6Ly9zcC5leGFtcGxlLmNvbS9kZW1vMS9pbmRleC5waHA/YWNzIiBJblJlc3BvbnNlVG89Ik9ORUxPR0lOXzRmZWUzYjA0NjM5NWM0ZTc1MTAxMWU5N2Y4OTAwYjUyNzNkNTY2ODUiLz4NCiAgICAgIDwvc2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uPg0KICAgIDwvc2FtbDpTdWJqZWN0Pg0KICAgIDxzYW1sOkNvbmRpdGlvbnMgTm90QmVmb3JlPSIyMDE0LTA3LTE3VDAxOjAxOjE4WiIgTm90T25PckFmdGVyPSIyMDI0LTAxLTE4VDA2OjIxOjQ4WiI+DQogICAgICA8c2FtbDpBdWRpZW5jZVJlc3RyaWN0aW9uPg0KICAgICAgICA8c2FtbDpBdWRpZW5jZT5odHRwOi8vc3AuZXhhbXBsZS5jb20vZGVtbzEvbWV0YWRhdGEucGhwPC9zYW1sOkF1ZGllbmNlPg0KICAgICAgPC9zYW1sOkF1ZGllbmNlUmVzdHJpY3Rpb24+DQogICAgPC9zYW1sOkNvbmRpdGlvbnM+DQogICAgPHNhbWw6QXV0aG5TdGF0ZW1lbnQgQXV0aG5JbnN0YW50PSIyMDE0LTA3LTE3VDAxOjAxOjQ4WiIgU2Vzc2lvbk5vdE9uT3JBZnRlcj0iMjAyNC0wNy0xN1QwOTowMTo0OFoiIFNlc3Npb25JbmRleD0iX2JlOTk2N2FiZDkwNGRkY2FlM2MwZWI0MTg5YWRiZTNmNzFlMzI3Y2Y5MyI+DQogICAgICA8c2FtbDpBdXRobkNvbnRleHQ+DQogICAgICAgIDxzYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkPC9zYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPg0KICAgICAgPC9zYW1sOkF1dGhuQ29udGV4dD4NCiAgICA8L3NhbWw6QXV0aG5TdGF0ZW1lbnQ+DQogICAgPHNhbWw6QXR0cmlidXRlU3RhdGVtZW50Pg0KICAgICAgPHNhbWw6QXR0cmlidXRlIE5hbWU9InVpZCIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDpiYXNpYyI+DQogICAgICAgIDxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPnRlc3Q8L3NhbWw6QXR0cmlidXRlVmFsdWU+DQogICAgICA8L3NhbWw6QXR0cmlidXRlPg0KICAgICAgPHNhbWw6QXR0cmlidXRlIE5hbWU9Im1haWwiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6YmFzaWMiPg0KICAgICAgICA8c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj50ZXN0QGV4YW1wbGUuY29tPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPg0KICAgICAgPC9zYW1sOkF0dHJpYnV0ZT4NCiAgICAgIDxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJlZHVQZXJzb25BZmZpbGlhdGlvbiIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDpiYXNpYyI+DQogICAgICAgIDxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPnVzZXJzPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPg0KICAgICAgICA8c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj5leGFtcGxlcm9sZTE8L3NhbWw6QXR0cmlidXRlVmFsdWU+DQogICAgICA8L3NhbWw6QXR0cmlidXRlPg0KICAgIDwvc2FtbDpBdHRyaWJ1dGVTdGF0ZW1lbnQ+DQogIDwvc2FtbDpBc3NlcnRpb24+DQo8L3NhbWxwOlJlc3BvbnNlPg";

    @RequestMapping("/decrypt")
    public void decryptSAMLResponse() {
        System.out.println("Private Key: " + privateKey);
        System.out.println("SAML: " + encryptedSAML);
        Response decodedSAMLResponse = unMarshallResponse(base64Decoder(encryptedSAML));
        Assertion assertion = getAssertion(decodedSAMLResponse, getPrivateKeyfromString(privateKey));
        String strX509Cert = assertion.getSignature().getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0).getValue();
        System.out.println(strX509Cert);
    }

    private Response unMarshallResponse(String samlResponse) {
        BasicParserPool ppMgr = new BasicParserPool();
        ppMgr.setNamespaceAware(true);
        Document document;
        try {
            System.out.println("Step0: " + samlResponse);
            document = ppMgr.parse(new ByteArrayInputStream(samlResponse.getBytes()));
            System.out.println("Step1: " + document);
            final Element responseRoot = document.getDocumentElement();
            System.out.println("Step2: " + responseRoot);
            UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(responseRoot);
            return (Response) unmarshaller.unmarshall(responseRoot);
        } catch (XMLParserException | UnmarshallingException e) {
            e.printStackTrace();
            return null;
        }
    }

    private String base64Decoder(String encodedValue) {
        String trimmed = encodedValue.replaceAll("\r\n", "");
        String base64DecodedResponse = new String(java.util.Base64.getDecoder().decode(trimmed));
        return base64DecodedResponse;
    }

    private Assertion getAssertion(Response samlResponse, PrivateKey privateKey) {
        Assertion assertion = decryptAssertion(samlResponse.getEncryptedAssertions().get(0), privateKey);
        return assertion;
    }

    private Assertion decryptAssertion(EncryptedAssertion encryptedAssertion, PrivateKey privateKey) {
        BasicX509Credential decryptionCredential = new BasicX509Credential();
        decryptionCredential.setPrivateKey(privateKey);
        KeyInfoCredentialResolver resolver = new StaticKeyInfoCredentialResolver(decryptionCredential);
        ChainingEncryptedKeyResolver keyResolver = new ChainingEncryptedKeyResolver();
        keyResolver.getResolverChain().add(new InlineEncryptedKeyResolver());
        keyResolver.getResolverChain().add(new EncryptedElementTypeEncryptedKeyResolver());
        keyResolver.getResolverChain().add(new SimpleRetrievalMethodEncryptedKeyResolver());

        Decrypter decrypter = new Decrypter(null, resolver, keyResolver);
        decrypter.setRootInNewDocument(true);
        Assertion assertion = null;
        try {
            assertion = decrypter.decrypt(encryptedAssertion);
        } catch (DecryptionException e) {
            e.printStackTrace();
        }
        return assertion;
    }

    public PrivateKey getPrivateKeyfromString(String privatekey) {
        StringBuilder pkcs8Lines = new StringBuilder();
        BufferedReader bufferedReader = new BufferedReader(new StringReader(privatekey));
        try {
            String line;
            while (true) {
                if (!((line = bufferedReader.readLine()) != null)) break;

                pkcs8Lines.append(line);
            }

            String pkcs8Pem = pkcs8Lines.toString();
            pkcs8Pem = pkcs8Pem.replace("-----BEGIN PRIVATE KEY-----", "");
            pkcs8Pem = pkcs8Pem.replace("-----END PRIVATE KEY-----", "");
            pkcs8Pem = pkcs8Pem.replaceAll("\\s+", "");

            byte[] pkcs8EncodedBytes = org.opensaml.xml.util.Base64.decode(pkcs8Pem);

            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = kf.generatePrivate(keySpec);
            return privateKey;
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }
}
