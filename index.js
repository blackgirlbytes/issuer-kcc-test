import { VerifiableCredential } from "@web5/credentials";
import { Web5 } from "@web5/api";
import { webcrypto } from "node:crypto";

// @ts-ignore
if (!globalThis.crypto) globalThis.crypto = webcrypto;

// Store the customer's DID URI
const customerDidUri = "did:dht:oubiyrhux5bupckyrb59de8hdr146jy41agjca94kyrxozth9jyo";

// Method to ask customer DWN for authorization to store a credential
async function requestForAuthorization(customerServerUrl, issuerDidUri) {
    try {
        const url = `${customerServerUrl}/authorize?issuerDid=${encodeURIComponent(issuerDidUri)}`;
        const response = await fetch(url);

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const result = await response.json();
        console.log("Authorization successful:", result);
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
    
    console.log(JSON.stringify(known_customer_credential, null, 2));  
    console.log(credential_token); 

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
                        can: ['read']
                    },
                    {
                        role: 'issuer', 
                        can: ['create']
                    },
                    {
                        who: 'author',
                        of: 'credential',
                        can: ['create','delete', 'update']
                    }, 
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

    const customerServerUrl = "http://localhost:5001"; // Adjust this URL as needed
    console.log('Requesting authorization for', issuerDidUri)
    const authorizationRequestResults = await requestForAuthorization(customerServerUrl, issuerDidUri)
    if (authorizationRequestResults.status == 202) {

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
    }
}

main();