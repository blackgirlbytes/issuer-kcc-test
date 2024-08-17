import { VerifiableCredential } from "@web5/credentials";
import { Web5 } from "@web5/api";
import { webcrypto } from "node:crypto";
import fetch from 'node-fetch';

// @ts-ignore
if (!globalThis.crypto) globalThis.crypto = webcrypto;

// Store the customer's DID URI
const customerDidUri = "did:dht:844zdw7i36qw7yti7oudc3nddk5qjoafixarx3wq7kemtwi5d7uo";

// Method to ask customer DWN for authorization to store a credential
async function requestForAuthorization(customerServerUrl, issuerDidUri) {
    try {
        const url = `${customerServerUrl}/authorize?issuerDid=${encodeURIComponent(issuerDidUri)}`;

        const response = await fetch(url);

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
     
        const result = await response.json();
        console.log("Authorization successful:", {message: result.message, status: result.status});
        return result;
    } catch (error) {
        console.error("Error authorizing with customer:", error);
        throw error;
    }
}

async function main() {
    // connect to DWN
    const { web5, did: issuerDidUri } = await Web5.connect();
    // get issuer bearer did
    const { did: issuerBearerDid } = await web5.agent.identity.get({ didUri: issuerDidUri });
    // Create credential
    const known_customer_credential = await VerifiableCredential.create({
        issuer: issuerDidUri, // Issuer's DID URI
        subject: customerDidUri, // Customer's DID URI 
        expirationDate: '2026-05-19T08:02:04Z',
        data: {
          countryOfResidence: "US", // 2 letter country code
          tier: "Gold", // optional KYC tier
          jurisdiction: {
            country: "US"
          }
        },
        credentialSchema: [
          {
            id: "https://vc.schemas.host/kcc.schema.json",
            type: "JsonSchema",
          }
        ],
        // (optional) specific proofs or checks you're attesting to
        evidence: [
            {
              "kind": "document_verification",
              "checks": ["passport", "utility_bill"]
            },
            {
              "kind": "sanction_screening",
              "checks": ["PEP"]
            }
          ]
    });
    // Sign Credential
    const credential_token = await known_customer_credential.sign({
        did: issuerBearerDid, // Issuer's Bearer DID
    });

    console.log('Your credential:',JSON.stringify(known_customer_credential, null, 2) )
    console.log('Your credential token:', credential_token); 

    // Get protocol definition via browser in hostURL/vc-protocol OR make api call 
    
    const vcProtocolDefinition = {
        protocol: 'https://vc-to-dwn.tbddev.org/vc-protocol',
        published: true,
        types: {
            credential: {
                schema: "https://vc-to-dwn.tbddev.org/vc-protocol/schema/credential",
                dataFormats: ['application/vc+jwt']
            },
            issuer: {
                schema: "https://vc-to-dwn.tbddev.org/vc-protocol/schema/issuer",
                dataFormats: ['text/plain']
            }
        },
        structure: {
            issuer: {
                $role: true,
            },
            credential: {
                $actions: [ 
                    {
                        who: 'anyone',
                        can: ['create', 'read']
                    },
                    {
                        role: 'issuer', 
                        can: ['create', 'read']
                    }
                ],
            }
        }
    };

    // Install protocol on local DWN
    const { protocol, status} = await web5.dwn.protocols.configure({
        message: {
          definition: vcProtocolDefinition
        }
    })
    // Install protocol on remote DWN
    await protocol.send(issuerDidUri);

    const customerServerUrl = "https://vc-to-dwn.tbddev.org"; // Adjust this URL as needed

    const authorizationRequestResults = await requestForAuthorization(customerServerUrl, issuerDidUri)

    if (authorizationRequestResults.status.code == 200 || authorizationRequestResults.status.code == 202) {
        const { record, status } = await web5.dwn.records.create({
            data: credential_token,
            message: {
                dataFormat: 'application/vc+jwt',
                protocol: vcProtocolDefinition.protocol,
                protocolPath: 'credential',
                protocolRole: 'issuer',
                schema: vcProtocolDefinition.types.credential.schema,
                recipient: customerDidUri,
            },
        });

        console.log(`You successfully stored a credential in customer's DWN:`, status);
    }
}

main();