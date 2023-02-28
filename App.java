package org.example.basicapp;

public class App {
    public static void main(String[] args) throws Exception {

        // paa
        ProductAttestationAuthorityActivation paa = new ProductAttestationAuthorityActivation();
        // Define the endpoint region for your sample.
        String endpointRegion = "ap-northeast-1";  // Substitute your region here, e.g. "ap-southeast-2"
        String paaCommonName = "Matter Test PAA FFF1"; // PAA common name
        String vid = "FFF1";
        String paaArn = paa.run(endpointRegion, paaCommonName, vid);

        //pai
        ProductAttestationIntermediateActivation pai = new ProductAttestationIntermediateActivation();
        String paiCommonName = "Matter Test PAI";
        String pid = "8000";
        String paiArn = pai.run(endpointRegion, paaArn, paiCommonName, vid, pid);

        //dac
        IssueDeviceAttestationCertificate dac = new IssueDeviceAttestationCertificate();
        String strCSR =
      "-----BEGIN CERTIFICATE REQUEST-----\n" +
      "MIHbMIGBAgEAMB8xHTAbBgNVBAMMFE1hdHRlciBUZXN0IERBQyAwMDAxMFkwEwYH\n" +
      "KoZIzj0CAQYIKoZIzj0DAQcDQgAE/N7ldO5jH+5IJpQJNj1qP6dejYHOPeRMntPA\n" +
      "hcDGhqBvBEeMAgf8A0DhVR9/l3UPEQNGurgMP4gzBpDCLG+oiqAAMAoGCCqGSM49\n" +
      "BAMCA0kAMEYCIQCw5N4LPe6AC1s2oZEcyt/LHmTZjqrE/Z75u1FrEu5FWAIhALVz\n" +
      "MOx9kQra5Jrzm4LRozhiZRjGAODi+LDasROmWr9I\n" +
      "-----END CERTIFICATE REQUEST-----\n";
        String dacCommonName = "Matter Test DAC 0001";
        String dacArn = dac.run(endpointRegion, paiArn, strCSR, dacCommonName, vid, pid);
    }

}
