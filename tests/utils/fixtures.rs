pub const ISSUER_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUr2bNKuBPOrAaxsR\nnbSH6hIhmNTxSGXshDSUD1a1y7ihRANCAARvbx3gzBkyPDz7TQIbjF+ef1IsxUwz\nX1KWpmlVv+421F7+c1sLqGk4HUuoVeN8iOoAcE547pJhUEJyf5Asc6pP\n-----END PRIVATE KEY-----\n";
pub const ISSUER_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEb28d4MwZMjw8+00CG4xfnn9SLMVM\nM19SlqZpVb/uNtRe/nNbC6hpOB1LqFXjfIjqAHBOeO6SYVBCcn+QLHOqTw==\n-----END PUBLIC KEY-----\n";
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
  "type": "IdentityCredential",
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
    "$.credentialSubject.is_over_65"
];