# UMA Resource Server minimal example

This is an minimal example of an UMA Resource Server implementation that can interact with our UMA Authorization Server.


## Installation

```
git clone git@github.com:SolidLabResearch/UMA_Resource_Server.git;
cd UMA_Resource_Server;
npm install;
```

## Starting the server

```
npm run start;
```

This starts up a very simple text-based server, where you can POST some string to a resource on the server URI
e.g. `http://localhost:<port>/resource1` with a Content-Type header of `text/plain`. This POST request does not
require authorization.

Next, to read this resource, a GET request to that same resource URI starts the UMA flow by returning 
`401 Unauthenticated` with a WWW_Authenticate header to forward you to the Authorization Server for the UMA flow.

```
WWW-Authenticate: UMA realm="solid",as_uri="http://localhost:4000/uma",ticket="93c435a6-1e91-4ba0-9bf0-126bb476cb03"
```

At the end of the client flow, when a valid token is provided that is retrieved from the Authorization Server,
the resource can be requested using this token provided in the Authorization header:
```
Authorization: Bearer eyJhbGciOiJFUzI1NiJ9.eyJwZXJtaXNzaW9u ... CgRPKQ
```

This will then be validated at the introspection endpoint of the Authorization Server, and the requested resource is returned.


**Note: we might still iterate on this token later, but the flow of retrieving the token, forwarding it in the Authorization header to the Resource Server and checking it at the introspection endpoint should remain the same!**

