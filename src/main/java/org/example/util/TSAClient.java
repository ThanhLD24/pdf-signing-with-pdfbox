package org.example.util;


import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Random;

import org.apache.pdfbox.util.Hex;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;

/**
 * Time Stamping Authority (TSA) Client [RFC 3161].
 * @author Vakhtang Koroghlishvili
 * @author John Hewson
 */
public class TSAClient
{

    private static final DigestAlgorithmIdentifierFinder ALGORITHM_OID_FINDER =
            new DefaultDigestAlgorithmIdentifierFinder();

    private final URL url;
    private final String username;
    private final String password;
    private final MessageDigest digest;

    // SecureRandom.getInstanceStrong() would be better, but sometimes blocks on Linux
    private static final Random RANDOM = new SecureRandom();

    /**
     *
     * @param url the URL of the TSA service
     * @param username user name of TSA
     * @param password password of TSA
     * @param digest the message digest to use
     */
    public TSAClient(URL url, String username, String password, MessageDigest digest)
    {
        this.url = url;
        this.username = username;
        this.password = password;
        this.digest = digest;
    }

    /**
     *
     * @param content
     * @return the time stamp token
     * @throws IOException if there was an error with the connection or data from the TSA server,
     *                     or if the time stamp response could not be validated
     */
    public TimeStampToken getTimeStampToken(InputStream content) throws IOException
    {
        digest.reset();
        DigestInputStream dis = new DigestInputStream(content, digest);
        while (dis.read() != -1)
        {
            // do nothing
        }
        byte[] hash = digest.digest();

        // 31-bit positive cryptographic nonce
        int nonce = RANDOM.nextInt(Integer.MAX_VALUE);

        // generate TSA request
        TimeStampRequestGenerator tsaGenerator = new TimeStampRequestGenerator();
        tsaGenerator.setCertReq(true);
        ASN1ObjectIdentifier oid = ALGORITHM_OID_FINDER.find(digest.getAlgorithm()).getAlgorithm();
        TimeStampRequest request = tsaGenerator.generate(oid, hash, BigInteger.valueOf(nonce));

        // get TSA response
        byte[] encodedRequest = request.getEncoded();
        byte[] tsaResponse = getTSAResponse(encodedRequest);

        TimeStampResponse response = null;
        try
        {
            response = new TimeStampResponse(tsaResponse);
            response.validate(request);
        }
        catch (TSPException e)
        {
            // You can visualize the hex with an ASN.1 Decoder, e.g. http://ldh.org/asn1.html
            if (response != null)
            {
                // See https://github.com/bcgit/bc-java/blob/4a10c27a03bddd96cf0a3663564d0851425b27b9/pkix/src/main/java/org/bouncycastle/tsp/TimeStampResponse.java#L159
                if ("response contains wrong nonce value.".equals(e.getMessage()))
                {
                    if (response.getTimeStampToken() != null)
                    {
                        TimeStampTokenInfo tsi = response.getTimeStampToken().getTimeStampInfo();
                        if (tsi != null && tsi.getNonce() != null)
                        {
                            // the nonce of the "wrong" test response is 0x3d3244ef
                        }
                    }
                }
            }
            throw new IOException(e);
        }

        TimeStampToken timeStampToken = response.getTimeStampToken();
        if (timeStampToken == null)
        {
            // https://www.ietf.org/rfc/rfc3161.html#section-2.4.2
            throw new IOException("Response from " + url +
                    " does not have a time stamp token, status: " + response.getStatus() +
                    " (" + response.getStatusString() + ")");
        }

        return timeStampToken;
    }

    // gets response data for the given encoded TimeStampRequest data
    // throws IOException if a connection to the TSA cannot be established
    private byte[] getTSAResponse(byte[] request) throws IOException
    {

        // todo: support proxy servers
        URLConnection connection = url.openConnection();
        connection.setDoOutput(true);
        connection.setDoInput(true);
        connection.setRequestProperty("Content-Type", "application/timestamp-query");


        if (username != null && password != null && !username.isEmpty() && !password.isEmpty())
        {
            String contentEncoding = connection.getContentEncoding();
            if (contentEncoding == null)
            {
                contentEncoding = StandardCharsets.UTF_8.name();
            }
            connection.setRequestProperty("Authorization",
                    "Basic " + Base64.getEncoder().encodeToString(
                            (username + ":" + password).getBytes(contentEncoding)));
        }

        // read response
        try (OutputStream output = connection.getOutputStream())
        {
            output.write(request);
        }
        catch (IOException ex)
        {
            throw ex;
        }


        byte[] response;
        try (InputStream input = connection.getInputStream())
        {
            response = input.readAllBytes();
        }
        catch (IOException ex)
        {
            throw ex;
        }


        return response;
    }
}
