package com.appsmith.external.helpers.restApiUtils.connections;

import com.appsmith.external.models.AwsSignatureV4Auth;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import reactor.core.publisher.Mono;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.UUID;

import static com.appsmith.external.constants.Authentication.AUTHORIZATION_HEADER;
import static com.appsmith.external.constants.Authentication.AWS_SECURITY_TOKEN_HEADER;

@Getter
@Setter
@Builder
@NoArgsConstructor(access = AccessLevel.PRIVATE)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class AwsSignatureV4Authentication extends APIConnection {
    private static final String HEADER_SIGNING_ALGORITHM = "AWS4-HMAC-SHA256";
    private String accessKeyId;
    private String secretAccessKey;
    private String sessionToken;
    private String service;
    private String region;

    public static Mono<AwsSignatureV4Authentication> create(AwsSignatureV4Auth awsSignatureV4Auth) {
        return Mono.just(
                AwsSignatureV4Authentication.builder()
                        .accessKeyId(awsSignatureV4Auth.getAccessKeyId())
                        .secretAccessKey(awsSignatureV4Auth.getSecretAccessKey())
                        .sessionToken(awsSignatureV4Auth.getSessionToken())
                        .build()
        );
    }

    @Override
    public Mono<ClientResponse> filter(ClientRequest request, ExchangeFunction next) {
        return Mono.justOrEmpty(ClientRequest.from(request)
                        .headers(header -> {
                            header.set(AUTHORIZATION_HEADER, getHeaderValue());
                            header.set(AWS_SECURITY_TOKEN_HEADER, sessionToken);
                        })
                        .build())
                // Carry on to next exchange function
                .flatMap(next::exchange)
                // Default to next exchange function if something went wrong
                .switchIfEmpty(next.exchange(request));
    }

    private String getHeaderValue() {
        DateFormat dateFormat = new SimpleDateFormat("YYYYMMDD");
        return HEADER_SIGNING_ALGORITHM + " Credential=" + accessKeyId + "/" + dateFormat.format(new Date()) + "/" + region + "/" + service + "/aws4_request, SignedHeaders=content-length;content-type;host;x-amz-date;x-amz-security-token, Signature=" + UUID.randomUUID();
    }
}
