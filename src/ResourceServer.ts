import bodyParser from "body-parser";
import express, { Request, Response } from "express"
import { httpbis, type SigningKey } from 'http-message-signatures';
import { JwkGenerator, SignedFetcher } from "./SignedFetcher";

export class ResourceServer {
    
    resources: Map<string, string> = new Map();
    port: number;
    app = express()
    baseUrl: string;
    authServer: string
    fetcher: SignedFetcher;
    keyGen: JwkGenerator;
    authServerUmaConfig: Promise<any>

    constructor(authServer: string, port?: number) {
        this.port = port || 3565;
        this.baseUrl = `http://localhost:${this.port}`
        // link UMA AS
        this.authServer = authServer;
        // Prepare signature keys etc...
        const keyMap = new Map()
        this.keyGen = new JwkGenerator("ES256", "jwks", keyMap);
        this.fetcher = new SignedFetcher({ fetch }, this.baseUrl, this.keyGen)
        this.authServerUmaConfig =  fetch(this.authServer+"/.well-known/uma2-configuration").then(config => config.json())

        // Start RS
        this.app.use(bodyParser.text())
        this.start()
    }

    public async start(): Promise<void> {
        this.app.get('/.well-known/jwks.json', (req, res) => { this.getJWKSConfig(req, res) })
        this.app.get('/*', (req, res) => { this.getResource(req, res) })
        this.app.post('/*',(req, res) => { this.postResource(req, res) })
        this.app.listen(this.port, () => {
            console.log(`Resource server started on port ${this.port}`);   
        })
    }

    public async getJWKSConfig(req: Request, res: Response): Promise<void> {
        const key = await this.keyGen.getPublicKey();
        res.json({ keys: [ Object.assign(key, { kid: 'TODO' }) ] })
    }

    public async getResource(req: Request, res: Response): Promise<void> {
        const resourceURI = this.baseUrl + req.url.trim()
        const asUmaConfig = await this.authServerUmaConfig

        const authHeader = req.header('Authorization')
        if (authHeader) {
            console.log(`Resource ${resourceURI} requested with Authentication header: ${authHeader}`)
            // todo: verify access token
            const token = authHeader.split("Bearer")[1].trim()

            const introspection_endpoint = asUmaConfig.introspection_endpoint

            try {
                const res = await this.fetcher.fetch(introspection_endpoint, {
                    method: 'POST',
                    headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': 'application/json',
                    },
                    body: `token_type_hint=access_token&token=${token}`,
                });
                
                const introspectionResponse = await res.json()
                console.log('Introspection check successful')
                console.log(JSON.stringify(introspectionResponse, null, 2))

                if (!introspectionResponse.active) throw new Error('Could not verify access token with introspection response.')
            } catch (e) {
                throw new Error(`Could not verify access token: ${e}`)
            }
        
            const resource = this.resources.get(resourceURI);
            res.send(resource || "Resource not found in Resource Server Storage")
            console.log(`Resource returned from ${resourceURI}`)

        } else {
            // Find UMA token endpoint
            const permission_endpoint = asUmaConfig.permission_endpoint
            console.log('permission_endpoint', permission_endpoint)

            // Ask for new ticket (https://solidlabresearch.github.io/authz-spec/specs/level0/#h-fed-res-ticket)
            const ticketRequest = await this.fetcher.fetch(permission_endpoint, {
                method: "POST",
                headers: { 
                    "Content-Type": "application/json",
                },
                body: JSON.stringify([{
                    "resource_id": resourceURI,
                    "resource_scopes": [ "urn:example:css:modes:read" ]
                }])
            })
            const response = await ticketRequest.json()
            console.log(`Retrieving AS ticket for request on ${resourceURI} -`, response)
            const umaAuthHeader = `UMA realm=\"solid\",as_uri=\"${this.authServer}\",ticket=\"${response.ticket}\"`;
            res.setHeader("WWW-Authenticate", umaAuthHeader)
            res.statusCode = 401
            res.send("401 Unauthenticated")
            
            console.log('Unauthenticated request - passed headers and as_uri link in WWW-Authenticate header')
        }
    }

    public async postResource(req: Request, res: Response): Promise<void> {
        const resourceURI = this.baseUrl + req.url.trim()
        if (this.resources.get(resourceURI)) { 
            res.send("Resource already exists in Demo UMA Resource Server!");
            return;
        }
        const resource = req.body as string;
        if (resource) {
            this.resources.set(resourceURI, resource);
        }
        console.log(`Resource saved at ${resourceURI}`)
        res.statusCode = 204;
        res.send(`Resource saved at ${resourceURI}`)
        this.registerResourceToAS(resourceURI)
    }

    private async registerResourceToAS(resourcePath: string): Promise<void> {
        console.log(`Creating resource registration for <${resourcePath}> at <${this.authServer}>`);

        const asUmaConfig = await this.authServerUmaConfig

        const description: any = {
            resource_scopes: [
                'urn:example:css:modes:read',
                'urn:example:css:modes:append',
                'urn:example:css:modes:create',
                'urn:example:css:modes:delete',
                'urn:example:css:modes:write',
            ]
        };

        const request = {
            url: asUmaConfig.resource_registration_endpoint,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            },
            body: JSON.stringify(description),
        };
    
        // do not await - registration happens in background to cope with errors etc.
        this.fetcher.fetch(asUmaConfig.resource_registration_endpoint, request).then(async resp => {
            if (resp.status !== 201) {
            throw new Error (`Resource registration request failed. ${await resp.text()}`);
            }
    
            const { _id: umaId } = await resp.json();
            
            if (!umaId || typeof umaId !== 'string') {
            throw new Error ('Unexpected response from UMA server; no UMA id received.');
            }
            
            console.log(`Resource registered at ${this.authServer} with id ${umaId}`)
        }).catch(error => {
            // TODO: Do something useful on error
            console.warn(
                `Something went wrong during UMA resource registration to create ${resourcePath}: ${(error as Error).message}`
            );
        });
    }
}