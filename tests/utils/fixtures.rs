// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

pub const ISSUER_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUr2bNKuBPOrAaxsR\nnbSH6hIhmNTxSGXshDSUD1a1y7ihRANCAARvbx3gzBkyPDz7TQIbjF+ef1IsxUwz\nX1KWpmlVv+421F7+c1sLqGk4HUuoVeN8iOoAcE547pJhUEJyf5Asc6pP\n-----END PRIVATE KEY-----\n";
pub const ISSUER_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEb28d4MwZMjw8+00CG4xfnn9SLMVM\nM19SlqZpVb/uNtRe/nNbC6hpOB1LqFXjfIjqAHBOeO6SYVBCcn+QLHOqTw==\n-----END PUBLIC KEY-----\n";
/// Second Issuer key — `issuer-key-2` of sd-jwt-python's General JSON test
/// vectors, which also signs `signatures[1]` of the RFC 9901 §8.3 example.
pub const ISSUER_KEY_2: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWsGosxrp0XK7VEvi\nPL9xBm3fBb7Xys2vLhPGhESNoXahRANCAARs36Gncg3QZkHc6VpCccM+Fjidmxlt\nDKjjBj7LU1YK8L2krB+Y7fc7d2kL0760mhWC8ozxvVIPtr57aDV5Qm1V\n-----END PRIVATE KEY-----\n";
pub const ISSUER_PUBLIC_KEY_2: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbN+hp3IN0GZB3OlaQnHDPhY4nZsZ\nbQyo4wY+y1NWCvC9pKwfmO33O3dpC9O+tJoVgvKM8b1SD7a+e2g1eUJtVQ==\n-----END PUBLIC KEY-----\n";
pub const HOLDER_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg5K5SCos8zf9zRemG\nGUl6yfok+/NiiryNZsvANWMhF+KhRANCAARMIARHX1m+7c4cXiPhbi99JWgcg/Ug\nuKUOWzu8J4Z6Z2cY4llm2TEBh1VilUOIW0iIq7FX7nnAhOreI0/Rdh2U\n-----END PRIVATE KEY-----\n";
pub const HOLDER_JWK_KEY: &str = r#"{
    "kty": "EC",
    "crv": "P-256",
    "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
    "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
}"#;
pub const ADDRESS_CLAIMS: &str = r#"{
    "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
    "iss": "https://example.com/issuer",
    "iat": 1683000000,
    "exp": 1883000000,
    "address": {
        "street_address": "Schulstr. 12",
        "locality": "Schulpforta",
        "region": "Sachsen-Anhalt",
        "country": "DE"
  }
}"#;
pub const ADDRESS_ONLY_STRUCTURED_JSONPATH: [&str; 4] = [
    "$.address.street_address",
    "$.address.locality",
    "$.address.region",
    "$.address.country",
];
pub const ADDRESS_ONLY_STRUCTURED_ONE_OPEN_JSONPATH: [&str; 3] = [
    "$.address.street_address",
    "$.address.locality",
    "$.address.region",
];
pub const ARRAYED_CLAIMS: &str = r#"
{
  "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
  "iss": "https://example.com/issuer",
  "iat": 1683000000,
  "exp": 1883000000,
  "addresses": [
    {
    "street_address": "Schulstr. 12",
    "locality": "Schulpforta",
    "region": "Sachsen-Anhalt",
    "country": "DE"
    },
    {
    "street_address": "456 Main St",
    "locality": "Anytown",
    "region": "NY",
    "country": "US"
    }
  ],
  "nationalities": [
    "US",
    "CA"
  ]
}"#;
pub const ARRAYED_CLAIMS_JSONPATH: [&str; 3] = [
    "$.addresses[1]",
    "$.addresses[1].country",
    "$.nationalities[0]",
];
pub const NESTED_ARRAY_CLAIMS: &str = r#"{
  "iss": "https://example.com/issuer",
  "iat": 1683000000,
  "exp": 1883000000,
  "nationalities": [
    ["IT", "UZ"],
    ["DE", "US"]
   ]
}"#;
pub const NESTED_ARRAY_JSONPATH: [&str; 3] = [
    "$.nationalities[0]",
    "$.nationalities[0][0]",
    "$.nationalities[0][1]",
];
pub const COMPLEX_EIDAS_CLAIMS: &str = r#"{
  "iss": "https://example.com/issuer",
  "iat": 1683000000,
  "exp": 1883000000,
  "verified_claims": {
    "verification": {
      "trust_framework": "eidas",
      "assurance_level": "high",
      "evidence": [
        {
          "type": "document",
          "time": "2022-04-22T11:30Z",
          "document": {
            "type": "idcard",
            "issuer": {
              "name": "c_d612",
              "country": "IT"
            },
            "number": "154554",
            "date_of_issuance": "2021-03-23",
            "date_of_expiry": "2031-03-22"
          }
        }
      ]
    },
    "claims": {
      "person_unique_identifier":
        "TINIT-fc0d9684-1bf0-4220-9642-8fe652c8c040",
      "given_name": "Raffaello",
      "family_name": "Mascetti",
      "date_of_birth": "1922-03-13",
      "gender": "M",
      "place_of_birth": {
        "country": "IT",
        "locality": "Firenze"
      },
      "nationalities": [
        "IT"
      ]
    }
  },
  "birth_middle_name": "Lello"
}"#;
pub const COMPLEX_EIDAS_JSONPATH: [&str; 7] = [
    "$.verified_claims.verification.evidence[0].document.issuer",
    "$.verified_claims.verification.evidence[0].document",
    "$.verified_claims.verification.evidence",
    "$.verified_claims.claims.date_of_birth",
    "$.verified_claims.claims.gender",
    "$.verified_claims.claims.place_of_birth",
    "$.verified_claims.claims.nationalities",
];
pub const W3C_VC_CLAIMS: &str = r#"{
  "iss": "https://example.com",
  "jti": "http://example.com/credentials/3732",
  "iat": 1683000000,
  "exp": 1883000000,
  "vct": "IdentityCredential",
  "credentialSubject": {
    "given_name": "John",
    "family_name": "Doe",
    "email": "johndoe@example.com",
    "phone_number": "+1-202-555-0101",
    "address": {
      "street_address": "123 Main St",
      "locality": "Anytown",
      "region": "Anystate",
      "country": "US"
    },
    "birthdate": "1940-01-01",
    "is_over_18": true,
    "is_over_21": true,
    "is_over_65": true
  }
}"#;
pub const W3C_VC_JSONPATH: [&str; 9] = [
    "$.credentialSubject.given_name",
    "$.credentialSubject.family_name",
    "$.credentialSubject.email",
    "$.credentialSubject.phone_number",
    "$.credentialSubject.address",
    "$.credentialSubject.birthdate",
    "$.credentialSubject.is_over_18",
    "$.credentialSubject.is_over_21",
    "$.credentialSubject.is_over_65",
];

/// RFC 9901 §8.3 example: an SD-JWT+KB in General JSON Serialization signed
/// by `issuer-key-1` ([ISSUER_KEY]) and `issuer-key-2` ([ISSUER_KEY_2]), with
/// `kid` in the unprotected headers. KB-JWT: aud
/// `https://verifier.example.org`, nonce `1234567890`.
pub const RFC_9901_GENERAL_JSON_EXAMPLE: &str = r#"{"payload":"eyJfc2QiOiBbIjRIQm42YUlZM1d0dUdHV1R4LXFVajZjZGs2V0JwWnlnbHRkRmF2UGE3TFkiLCAiOHNtMVFDZjAyMXBObkhBQ0k1c1A0bTRLWmd5Tk9PQVljVGo5SE5hQzF3WSIsICJjZ0ZkaHFQbzgzeFlObEpmYWNhQ2FhN3VQOVJDUjUwVkU1UjRMQVE5aXFVIiwgImpNQ1hWei0tOWI4eDM3WWNvRGZYUWluencxd1pjY2NmRlJCQ0ZHcWRHMm8iXSwgImlzcyI6ICJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsICJpYXQiOiAxNjgzMDAwMDAwLCAiZXhwIjogMTg4MzAwMDAwMCwgIl9zZF9hbGciOiAic2hhLTI1NiIsICJjbmYiOiB7Imp3ayI6IHsia3R5IjogIkVDIiwgImNydiI6ICJQLTI1NiIsICJ4IjogIlRDQUVSMTladnUzT0hGNGo0VzR2ZlNWb0hJUDFJTGlsRGxzN3ZDZUdlbWMiLCAieSI6ICJaeGppV1diWk1RR0hWV0tWUTRoYlNJaXJzVmZ1ZWNDRTZ0NGpUOUYySFpRIn19fQ","signatures":[{"header":{"disclosures":["WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd","WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImdpdmVuX25hbWUiLCAiSm9obiJd"],"kid":"issuer-key-1","kb_jwt":"eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9.eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUub3JnIiwgImlhdCI6IDE3NDg1MzcyNDQsICJzZF9oYXNoIjogInFieUlXUDNwaFZneEVzRFJpd2R3OVc2QkozZHhpUEx1bWNZcFBidTRFYjgifQ.VyZqxaVHh1XE6M-kuax_7Laq42uFDrx17lLG2jluyKgy_PqC85z4DVpISdMZDdSANGs-0zN2N7xnM-E1Pg0sOw"},"protected":"eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0","signature":"dz1N3uvhVHJjldyXwppmBLieTj0vuBMbzL06rnrLIuxEQb9BHoIOwGrWh-UadW4orRpEiEtjf7xyHDONMJ6tBw"},{"header":{"kid":"issuer-key-2"},"protected":"eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0","signature":"kuXio_U88RH_-fihAPET4AFUjj0BpxsT6yddMFIr6pfHKtAe0FOJNWQxU42rfnORuNQNTgGsf2A8LjEba5inNg"}]}"#;
